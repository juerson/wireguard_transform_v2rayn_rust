use csv::ReaderBuilder;
use lazy_static::lazy_static;
use rand::{prelude::SliceRandom, thread_rng, Rng};
use regex::Regex;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    error::Error,
    fs::{self, File},
    io::{self, BufRead, BufReader, Write},
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};
use urlencoding::encode;

lazy_static! {
    static ref DOMAIN_RE: Regex = Regex::new(r"\b^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:\.[a-zA-Z]{2})?$\b").unwrap(); // 匹配域名(子域名)
    static ref DOMAIN_WITH_PORT_RE: Regex = Regex::new(r"\b^(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\:[0-9]{1,5}$\b").unwrap(); // 匹配带端口的域名(子域名)
    static ref IPV4_WITH_PORT_RE: Regex = Regex::new(r#"\b^(?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}$\b"#).unwrap();
    static ref IPV6_WITH_PORT_RE: Regex = Regex::new(r#"^\[([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\]:[0-9]{1,5}$"#).unwrap();
    static ref IPV4_CIDR_RE: Regex = Regex::new(r#"\b^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})$\b"#).unwrap();
    static ref IPV6_CIDR_RE: Regex = Regex::new(r#"^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$|^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))"#).unwrap();
    static ref IPV4_REGEX: Regex = Regex::new(r#"\b^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$\b"#).unwrap();
    static ref IPV6_REGEX: Regex = Regex::new(r#"^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:))$"#).unwrap();
}

fn main() {
    println!("    <<<<<<<< 本程序的功能：批量更换WireGuard链接中的address和port，生成大量的WireGuard节点！ >>>>>>>>");
    println!("{:-<106}", "");
    let filename = "ips-v4.txt";
    let ips_or_cidrs = read_file_lines(filename);
    let wireguard_parameters = read_wireguard_key_parameters("WireGuard.conf");

    // 存放没有端口的IP和域名
    let mut ips = HashSet::new();
    // 存放有端口的IP和域名
    let mut ip_with_port_vector: Vec<String> = Vec::new();

    // 读取当前目录中所有csv文件，并将csv文件第一列IP:PORT值存入ip_with_port_vector中
    match find_csv_files_in_current_directory() {
        Ok(csv_files) => {
            // 使用 for 循环迭代 csv_files 中的文件名
            for csv_file in csv_files.iter() {
                // 读取csv第一列的IP:PORT值（所有值）
                match read_csv_first_column_values(csv_file) {
                    Ok(values) => {
                        ip_with_port_vector.extend(values);
                    }
                    Err(_) => {}
                }
            }
        }
        Err(_) => {}
    }

    let ports_vec: Vec<u16> = vec![
        500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946,
        955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371, 2408,
        2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281,
        7559, 8319, 8742, 8854, 8886,
    ];
    let selected_ports = select_ports(ports_vec); // 选择端口

    for ipaddr in &ips_or_cidrs {
        if DOMAIN_WITH_PORT_RE.is_match(ipaddr) {
            // 判断有端口的域名
            ip_with_port_vector.push(ipaddr.to_string());
        } else if DOMAIN_RE.is_match(ipaddr) {
            // 判断没有端口的域名
            ips.insert(ipaddr.to_string());
        } else if IPV4_WITH_PORT_RE.is_match(ipaddr) {
            // 判断是带端口的IPv4地址
            ip_with_port_vector.push(ipaddr.to_string());
        } else if IPV6_WITH_PORT_RE.is_match(ipaddr) {
            // 判断是带端口的IPv6地址
            ip_with_port_vector.push(ipaddr.to_string());
        } else if IPV4_REGEX.is_match(ipaddr) {
            // 先使用正则判断是否为IPv4地址，然后将字符串解析为IPv4地址，成功就插入到ips HashSet中
            if let Ok(ipv4) = ipaddr.parse::<Ipv4Addr>() {
                ips.insert(ipv4.to_string());
            }
        } else if IPV6_REGEX.is_match(ipaddr) {
            // 先使用正则判断是否为IPv6地址，然后将字符串解析为IPv6地址，成功就插入到ips HashSet中
            if let Ok(ipv6) = ipaddr.parse::<Ipv6Addr>() {
                ips.insert(ipv6.to_string());
            }
        } else if IPV4_CIDR_RE.is_match(ipaddr) {
            // 判断是IPv4 CIDR,生成CIDR范围内所有IPv4地址并插入到ips HashSet中
            InsertIPS::generate_and_insert_ipv4_addresses(&ipaddr, &mut ips);
        } else if IPV6_CIDR_RE.is_match(ipaddr) {
            // 判断是IPv6 CIDR，生成CIDR范围内随机IPv6地址并插入到ips HashSet中
            InsertIPS::generate_and_insert_ipv6_addresses(&ipaddr, &mut ips);
        } else {
            // 省略不合法的字符串
        }
    }

    // 为IP地址添加端口
    let ip_with_port_generate = add_port(&ips, &selected_ports);

    // 合并到ip_with_port_vector中
    ip_with_port_vector.extend(ip_with_port_generate);

    // 构建wireguard节点的链接
    let links_results = build_wireguard_links(wireguard_parameters, ip_with_port_vector);

    // 显示100个链接（效果）
    display_100_links(links_results.clone());

    // 写入txt文件中
    write_to_file(links_results, "output.txt");

    InsertIPS::user_input(); // 这里作为暂停作用，等待用户按Enter键或关闭窗口，防止程序迅速退出
}

struct IpGenerator;
impl IpGenerator {
    // 生成所有IPv4地址
    fn generate_all_ipv4_addresses(cidr: &str) -> Vec<Ipv4Addr> {
        let (network, mask) = IpGenerator::parse_ipv4_cidr(cidr).expect("Invalid IPv4 CIDR");
        let host_bits = 32 - mask;
        let total_addresses = 2u32.pow(host_bits);
        (0..total_addresses)
            .map(|i| Ipv4Addr::from(u32::from(network) + i))
            .collect()
    }
    // 生成随机IPv6地址（指定数量）
    fn generate_random_ipv6_addresses(cidr: &str, max_count: usize) -> Vec<Ipv6Addr> {
        let (ip, mask) = IpGenerator::parse_ipv6_cidr(cidr).expect("Invalid IPv6 CIDR");
        let mut rng = thread_rng();
        let mut ip_range = Vec::new();
        for _ in 0..max_count {
            let random_ip = rng.gen_range(0..(1u128 << (128 - mask)));
            let ip = (u128::from_be_bytes(ip.octets()) & !((1u128 << mask) - 1)) + random_ip;
            ip_range.push(Ipv6Addr::from(ip));
        }
        ip_range
    }
    // 解析IPv4 CIDR(判断是否为有效的IPv4 CIDR)
    fn parse_ipv4_cidr(cidr: &str) -> Result<(Ipv4Addr, u32), &'static str> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err("Invalid IPv4 CIDR format");
        }
        let network = Ipv4Addr::from_str(parts[0]).map_err(|_| "Invalid IPv4 address")?;
        let mask: u32 = parts[1].parse().map_err(|_| "Invalid subnet mask")?;
        Ok((network, mask))
    }
    // 解析IPv6 CIDR(判断是否为有效的IPv6 CIDR)
    fn parse_ipv6_cidr(cidr: &str) -> Result<(Ipv6Addr, u8), &'static str> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() == 2 {
            let ip = Ipv6Addr::from_str(parts[0]).map_err(|_| "Invalid IPv6 address")?;
            let mask = u8::from_str(parts[1]).map_err(|_| "Invalid subnet mask")?;
            return Ok((ip, mask));
        }
        Err("Invalid IPv6 CIDR format")
    }
}

struct InsertIPS;
impl InsertIPS {
    // 生成IPv4地址并插入到ips HashSet中
    fn generate_and_insert_ipv4_addresses(cidr: &str, ips: &mut HashSet<String>) {
        let ip_range_v4 = IpGenerator::generate_all_ipv4_addresses(cidr);
        for ip in ip_range_v4.iter() {
            ips.insert(ip.to_string());
        }
    }
    // 生成IPv6地址并插入到ips HashSet中
    fn generate_and_insert_ipv6_addresses(cidr: &str, ips: &mut HashSet<String>) {
        print!(
            "IPv6 CIDR:{}，需要生成多少个随机IPv6地址？(默认500个)：",
            cidr
        );
        io::stdout().flush().expect("刷新输出缓冲区失败");
        let max_count_v6 = Self::user_input().parse::<usize>().unwrap_or(500);
        let ip_range_v6 = IpGenerator::generate_random_ipv6_addresses(cidr, max_count_v6);
        for ip in &ip_range_v6 {
            ips.insert(ip.to_string());
        }
    }
    // 获取用户输入
    fn user_input() -> String {
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("读取输入时发生错误");
        input.trim().to_owned()
    }
}

// 添加端口
fn add_port(ip_list: &HashSet<String>, ports: &[u16]) -> HashSet<String> {
    let mut ips_with_port = HashSet::new();
    if ip_list.len() > 0 {
        for ip in ip_list {
            let mut new_ports: Vec<u16> = ports.iter().cloned().collect();
            // 确保IP地址构建的端口中，一定含有2408端口
            if !ports.contains(&2408) {
                new_ports.push(2408);
            }
            for port in new_ports {
                let socket_addr_str = if ip.contains(":") && !ip.contains("[") && !ip.contains("]")
                {
                    if IPV6_REGEX.is_match(ip) {
                        // IPv6 地址需要加中括号
                        format!("[{}]:{}", ip, port)
                    } else if IPV4_WITH_PORT_RE.is_match(ip) {
                        // 含端口的IPv4地址
                        format!("{}", ip)
                    } else {
                        // 有冒号，但是不是IPv6地址，也不是含端口的IPv4地址，可能是含有端口的域名
                        format!("{}", ip)
                    }
                } else {
                    format!("{}:{}", ip, port)
                };
                ips_with_port.insert(socket_addr_str);
            }
        }
    }
    ips_with_port
}

// 选择端口，由用户输入，没有输入或输入错误，默认选择20个随机端口
fn select_ports(ports_vec: Vec<u16>) -> Vec<u16> {
    let ports_length = ports_vec.len();
    let num_select = input(
        format!(
            "本程序内置了{}个Cloudflare WARP端口，默认随机选择其中的20个。\n您可以选择指定数量的随机端口(可选范围：1~{})：",
            ports_length, ports_length
        )
        .as_str(),
    );
    let check_port_number = match num_select.parse::<usize>() {
        Ok(n) if n > 0 && n <= ports_length => n,
        _ => 20,
    };
    let mut rng = rand::thread_rng();
    let random_ports: Vec<u16> = ports_vec
        .choose_multiple(&mut rng, check_port_number)
        .cloned()
        .collect();
    random_ports
}

// 捕捉用户输入的内容
fn input(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().expect("无法刷新缓冲区");
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("无法读取输入");
    input.trim().to_string()
}

// 读取wireguard的配置文件参数
fn read_wireguard_key_parameters(file: &str) -> std::collections::HashMap<String, String> {
    let mut wireguard_param = std::collections::HashMap::new();
    let contents = fs::read_to_string(file).expect("无法读取文件");
    let lines: Vec<&str> = contents.lines().collect();

    for line in lines {
        if line.starts_with("PrivateKey") {
            wireguard_param.insert(
                "PrivateKey".to_string(),
                line.replace(" ", "").replace("PrivateKey=", "").to_string(),
            );
        } else if line.starts_with("PublicKey") {
            wireguard_param.insert(
                "PublicKey".to_string(),
                line.replace(" ", "").replace("PublicKey=", "").to_string(),
            );
        } else if line.starts_with("Address") {
            // 清理行，移除空格和"Address="字符串，然后切割得到地址列表
            let cleaned_line = line.replace(" ", "").replace("Address=", "");
            let new_addresses: Vec<&str> = cleaned_line.split(',').collect();
            // 获取已经存在的地址列表，如果不存在，就用空列表代替
            let mut existing_addresses: Vec<String> = match wireguard_param.get("Address") {
                Some(val) => val.split(',').map(|s| s.to_string()).collect(),
                None => vec![],
            };
            // 将新地址添加到已经存在的地址列表中
            for new_address in new_addresses {
                existing_addresses.push(new_address.to_string());
            }
            // 存储合并后的地址列表
            wireguard_param.insert("Address".to_string(), existing_addresses.join(","));
        } else if line.starts_with("MTU") {
            wireguard_param.insert(
                "MTU".to_string(),
                line.replace(" ", "").replace("MTU=", "").to_string(),
            );
        } else if line.starts_with("Reserved") {
            wireguard_param.insert(
                "Reserved".to_string(),
                line.replace(" ", "").replace("Reserved=", "").to_string(),
            );
        }
    }

    wireguard_param
}

// 读取ips-v4.txt的内容，并返回Vec<String>
fn read_file_lines(filename: &str) -> Vec<String> {
    // 打开文件并读取内容
    let file = match File::open(filename) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Failed to open file: {}", e);
            return Vec::new();
        }
    };
    // 使用 BufReader 来缓冲读取文件内容
    let reader = BufReader::new(file);
    // 创建一个 HashSet 来存储唯一的行
    let mut unique_lines: HashSet<String> = HashSet::new();
    // 创建一个 VecDeque 来存储非空行
    let mut lines: VecDeque<String> = VecDeque::new();
    // 逐行读取文件内容并处理
    for line in reader.lines() {
        if let Ok(line) = line {
            // 去除空行和重复行
            if !line.trim().is_empty() && unique_lines.insert(line.clone()) {
                lines.push_back(line);
            }
        }
    }
    // 转换为 Vec<String>
    lines.into()
}

fn write_to_file(set_contents: Vec<String>, output_file: &str) {
    // 将 HashSet 中的所有字符串用换行符拼接成一个大字符串
    let contents = set_contents
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<&str>>()
        .join("\n");
    // 创建一个文件并打开以写入模式
    let mut file = match File::create(output_file) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Failed to create file: {}", e);
            return;
        }
    };
    // 将拼接好的字符串写入文件
    if let Err(e) = file.write_all(contents.as_bytes()) {
        eprintln!("Failed to write to file: {}", e);
        return;
    }
    println!(
        "   <<<<<<<< 温馨提示：WireGuard节点的链接，全部生成成功，并且成功将数据写入{}文件中! >>>>>>>>",
        output_file
    );
}

fn build_wireguard_links(
    wireguard_parameters: HashMap<String, String>,
    ip_with_port_vec: Vec<String>,
) -> Vec<String> {
    let default = &"".to_string();
    let default_mtu = &"1420".to_string();
    // 获取wireguard配置文件中的参数
    let public_key = wireguard_parameters.get("PublicKey").unwrap_or(default);
    let private_key = wireguard_parameters.get("PrivateKey").unwrap_or(default);
    let address = wireguard_parameters.get("Address").unwrap_or(default);
    let reserved = wireguard_parameters.get("Reserved").unwrap_or(default);
    let mtu = wireguard_parameters.get("MTU").unwrap_or(default_mtu);
    // 接收生成wireguard链接的结果
    let mut results: Vec<String> = Vec::new();
    for ip_with_port in ip_with_port_vec {
        let links;
        // 是""字符的，就走""分支,否则走_分支。
        match reserved.as_str() {
            "" => {
                links = format!(
                    "wireguard://{}@{}/?publickey={}&address={}&mtu={}#{}",
                    encode(private_key),
                    ip_with_port,
                    encode(public_key),
                    encode(address),
                    encode(mtu),
                    encode(&ip_with_port.to_string()),
                );
            }
            _ => {
                links = format!(
                    "wireguard://{}@{}/?publickey={}&reserved={}&address={}&mtu={}#{}",
                    encode(private_key),
                    ip_with_port,
                    encode(public_key),
                    encode(reserved),
                    encode(address),
                    encode(mtu),
                    encode(&ip_with_port.to_string()),
                );
            }
        }
        results.push(links);
    }

    results
}

fn display_100_links(hash_set: Vec<String>) {
    println!("\n{:-<43} WireGuard节点如下: {:-<43}", "", "");

    // 返回前100个元素，不足100个就返回全部
    let sliced_vec: Vec<&String> = hash_set.iter().take(100).collect();

    // 由迭代器产生元素的索引及其引用的元组，这里最多100个索引及其引用
    for (_index, item) in sliced_vec.iter().enumerate() {
        println!("{}", item);
    }
    // 如果元素个数超过100，则打印"......"省略剩余链接
    if hash_set.len() > 100 {
        println!("\n.........省略后面的节点.........\n"); // 先省略再换行
        println!("{:-<106}", "");
    } else {
        println!("{:-<106}", "");
    }
}

// 读取csv文件中第一列的IP:PORT(除了第一行标题)
fn read_csv_first_column_values(filename: &str) -> Result<Vec<String>, Box<dyn Error>> {
    // 检查文件是否存在
    if !fs::metadata(filename)?.is_file() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "File not found").into());
    }
    // 打开CSV文件
    let file = File::open(filename)?;
    // 创建CSV读取器
    let mut rdr = ReaderBuilder::new().has_headers(true).from_reader(file);
    // 创建一个Vec来存储第一列的内容
    let mut first_column_values: Vec<String> = Vec::new();
    // 逐行读取CSV文件
    for result in rdr.records() {
        // 读取每一行的记录
        let record = result?;
        // 获取第一列的值
        if let Some(value) = record.get(0) {
            // 再次确定读取到数据是否符合IP:PORT格式
            if IPV4_WITH_PORT_RE.is_match(value)
                || IPV6_WITH_PORT_RE.is_match(value)
                || DOMAIN_WITH_PORT_RE.is_match(value)
            {
                first_column_values.push(value.to_owned());
            }
        }
    }
    Ok(first_column_values)
}

// 获取当前目录下的所有 CSV 文件路径
fn find_csv_files_in_current_directory() -> Result<Vec<String>, Box<dyn Error>> {
    // 获取当前目录的文件迭代器
    let current_dir = fs::read_dir(".")?;
    // 创建一个 Vec 来存储 CSV 文件的路径
    let mut csv_files: Vec<String> = Vec::new();
    // 遍历当前目录下的文件
    for entry in current_dir {
        let entry = entry?;
        let path = entry.path();
        // 检查文件是否是 CSV 文件
        if let Some(extension) = path.extension() {
            if extension == "csv" {
                // 将 CSV 文件的路径添加到 Vec 中
                if let Some(file_name) = path.to_str() {
                    csv_files.push(file_name.to_string());
                }
            }
        }
    }
    Ok(csv_files)
}
