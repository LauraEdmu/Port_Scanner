use std::process::Command;
use std::env;
use quick_xml::de::from_str;
use prettytable::{Table, row};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct NmapRun {
    #[serde(rename = "host")]
    hosts: Option<Vec<Host>>, // Hosts information
}

#[derive(Debug, Deserialize)]
struct Host {
    #[serde(rename = "address")]
    addresses: Vec<Address>, // Multiple addresses per host
    #[serde(rename = "ports")]
    ports: Option<Ports>, // Ports might not be present
}

#[derive(Debug, Deserialize)]
struct Address {
    #[serde(rename = "addr")]
    addr: String, // The actual address (IP or MAC)
    #[serde(rename = "addrtype")]
    addrtype: String, // Type of address (ipv4, ipv6, mac)
}

#[derive(Debug, Deserialize, Default)]
struct Ports {
    #[serde(rename = "extraports")]
    extraports: Option<ExtraPorts>, // Handling extraports (closed ports)
    #[serde(rename = "port")]
    ports: Option<Vec<Port>>, // Ports might not be present
}

#[derive(Debug, Deserialize)]
struct ExtraPorts {
    #[serde(rename = "state")]
    state: String, // State of the extraports (usually "closed")
}

#[derive(Debug, Deserialize)]
struct Port {
    #[serde(rename = "portid")]
    port_id: u16,
    #[serde(rename = "state")]
    state: PortState,
}

#[derive(Debug, Deserialize)]
struct PortState {
    #[serde(rename = "state")]
    state: String,
}

fn run_nmap_scan(target: &str) -> Result<String, String> {
    let output = Command::new("nmap")
        .arg("-F") // Fast scan of common ports
        .arg("-oX") // Output in XML format
        .arg("-") // Output to stdout
        .arg(target) // Scan the specified target
        .output()
        .map_err(|e| format!("Failed to run nmap: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string());
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn parse_nmap_output(xml_data: &str) -> Result<NmapRun, String> {
    from_str(xml_data).map_err(|e| format!("Failed to parse XML: {}", e))
}

fn display_scan_results(nmap_run: NmapRun) {
    if let Some(hosts) = nmap_run.hosts {
        let mut table = Table::new();
        table.add_row(row!["IP Address", "Open Ports"]);

        for host in hosts {
            // Handle multiple addresses per host
            for address in host.addresses {
                // Only display IP addresses (ignore MAC addresses)
                if address.addrtype == "ipv4" || address.addrtype == "ipv6" {
                    let open_ports: Vec<String> = host.ports
                        .as_ref()
                        .and_then(|ports| ports.ports.as_ref()) // Safely handle missing ports
                        .map_or(vec![], |ports| {
                            ports
                                .iter()
                                .filter(|port| port.state.state == "open")
                                .map(|port| port.port_id.to_string())
                                .collect()
                        });

                    table.add_row(row![address.addr, open_ports.join(", ")]);
                }
            }
        }

        table.printstd();
    } else {
        println!("No hosts found.");
    }
}

fn main() {
    // Get the target IP or range from the command-line arguments
    let args: Vec<String> = env::args().collect();
    let target = if args.len() > 1 {
        &args[1]
    } else {
        "127.0.0.1" // Default to localhost if no target is specified
    };

    match run_nmap_scan(target) {
        Ok(xml_data) => {
            match parse_nmap_output(&xml_data) {
                Ok(nmap_run) => display_scan_results(nmap_run),
                Err(err) => eprintln!("Error parsing nmap output: {}", err),
            }
        }
        Err(err) => eprintln!("Error running nmap: {}", err),
    }
}
