"""
Nmap adapter for port scanning and service discovery.

Provides a simple interface to nmap for common scanning tasks.
"""

from typing import List, Optional

from boxi.artifacts import Service, ServiceState, Target
from boxi.config import get_settings
from boxi.logging_config import get_logger, log_tool_missing
from boxi.utils.process import ProcessError, ProcessTimeout, run
from boxi.utils.text import parse_nmap_output

logger = get_logger(__name__)


class NmapAdapter:
    """Adapter for nmap port scanning."""
    
    def __init__(self):
        self.settings = get_settings()
        self.tool_path = self.settings.get_tool_path("nmap")
        self.timeout = self.settings.nmap_timeout
    
    def is_available(self) -> bool:
        """Check if nmap is available."""
        return self.tool_path is not None
    
    def quick_scan(self, target: str) -> List[Service]:
        """
        Perform a quick TCP port scan of common ports.
        
        Args:
            target: Target IP or hostname
            
        Returns:
            List of discovered services
        """
        if not self.is_available():
            log_tool_missing("nmap", "port scanning")
            return []
        
        cmd = [
            self.tool_path,
            "-sS",  # SYN scan
            "-T4",  # Timing template (aggressive)
            "--top-ports", "1000",  # Scan top 1000 ports
            "-n",   # No DNS resolution
            target
        ]
        
        try:
            logger.debug(f"Running nmap quick scan against {target}")
            result = run(cmd, timeout=self.timeout)
            
            return self._parse_scan_result(result.stdout, target)
            
        except (ProcessError, ProcessTimeout) as e:
            logger.error(f"Nmap scan failed: {e}")
            return []
    
    def full_scan(self, target: str, ports: Optional[str] = None) -> List[Service]:
        """
        Perform a comprehensive TCP scan with service detection.
        
        Args:
            target: Target IP or hostname
            ports: Port specification (e.g. "1-1000" or "22,80,443")
            
        Returns:
            List of discovered services with banners
        """
        if not self.is_available():
            log_tool_missing("nmap", "port scanning")
            return []
        
        cmd = [
            self.tool_path,
            "-sS",  # SYN scan
            "-sV",  # Service version detection
            "-T4",  # Timing template
            "-n",   # No DNS resolution
        ]
        
        if ports:
            cmd.extend(["-p", ports])
        else:
            cmd.extend(["--top-ports", "1000"])
        
        cmd.append(target)
        
        try:
            logger.debug(f"Running nmap full scan against {target}")
            result = run(cmd, timeout=self.timeout * 2)  # Full scan takes longer
            
            return self._parse_scan_result(result.stdout, target)
            
        except (ProcessError, ProcessTimeout) as e:
            logger.error(f"Nmap scan failed: {e}")
            return []
    
    def udp_scan(self, target: str, top_ports: int = 100) -> List[Service]:
        """
        Perform a UDP port scan.
        
        Args:
            target: Target IP or hostname
            top_ports: Number of top UDP ports to scan
            
        Returns:
            List of discovered UDP services
        """
        if not self.is_available():
            log_tool_missing("nmap", "UDP scanning")
            return []
        
        cmd = [
            self.tool_path,
            "-sU",  # UDP scan
            "-T4",
            "--top-ports", str(top_ports),
            "-n",
            target
        ]
        
        try:
            logger.debug(f"Running nmap UDP scan against {target}")
            result = run(cmd, timeout=self.timeout * 3)  # UDP scans are slower
            
            return self._parse_scan_result(result.stdout, target)
            
        except (ProcessError, ProcessTimeout) as e:
            logger.error(f"Nmap UDP scan failed: {e}")
            return []
    
    def os_detection(self, target: str) -> Optional[Target]:
        """
        Perform OS detection scan.
        
        Args:
            target: Target IP or hostname
            
        Returns:
            Target with OS information if detected
        """
        if not self.is_available():
            log_tool_missing("nmap", "OS detection")
            return None
        
        cmd = [
            self.tool_path,
            "-O",   # OS detection
            "-sS",  # SYN scan for open ports
            "--top-ports", "100",
            "-n",
            target
        ]
        
        try:
            logger.debug(f"Running nmap OS detection against {target}")
            result = run(cmd, timeout=self.timeout)
            
            return self._parse_os_result(result.stdout, target)
            
        except (ProcessError, ProcessTimeout) as e:
            logger.error(f"Nmap OS detection failed: {e}")
            return None
    
    def script_scan(self, target: str, scripts: List[str], ports: Optional[str] = None) -> str:
        """
        Run nmap scripts against target.
        
        Args:
            target: Target IP or hostname
            scripts: List of script names to run
            ports: Port specification (optional)
            
        Returns:
            Raw nmap output
        """
        if not self.is_available():
            log_tool_missing("nmap", "script scanning")
            return ""
        
        cmd = [
            self.tool_path,
            "-sS",
            "--script", ",".join(scripts),
            "-n",
        ]
        
        if ports:
            cmd.extend(["-p", ports])
        
        cmd.append(target)
        
        try:
            logger.debug(f"Running nmap scripts {scripts} against {target}")
            result = run(cmd, timeout=self.timeout * 2)
            
            return result.stdout
            
        except (ProcessError, ProcessTimeout) as e:
            logger.error(f"Nmap script scan failed: {e}")
            return ""
    
    def _parse_scan_result(self, output: str, target_host: str) -> List[Service]:
        """Parse nmap scan output into Service objects."""
        services = []
        
        # Parse basic port information
        port_info = parse_nmap_output(output)
        
        for port_data in port_info:
            # Map nmap state to our enum
            state = ServiceState.UNKNOWN
            if port_data['state'] == 'open':
                state = ServiceState.OPEN
            elif port_data['state'] == 'closed':
                state = ServiceState.CLOSED
            elif port_data['state'] == 'filtered':
                state = ServiceState.FILTERED
            
            # Extract service name and banner
            service_info = port_data.get('service', '')
            service_name = None
            banner = None
            
            if service_info:
                # Simple parsing - more sophisticated parsing could be added
                parts = service_info.split()
                if parts:
                    service_name = parts[0]
                    if len(parts) > 1:
                        banner = ' '.join(parts[1:])
            
            service = Service(
                target_host=target_host,
                port=int(port_data['port']),
                protocol=port_data['protocol'],
                service_name=service_name,
                banner=banner,
                state=state
            )
            
            services.append(service)
        
        logger.info(f"Discovered {len(services)} services on {target_host}")
        return services
    
    def _parse_os_result(self, output: str, target_host: str) -> Optional[Target]:
        """Parse nmap OS detection output."""
        os_guess = None
        domain_joined = None
        
        # Look for OS detection lines
        for line in output.split('\n'):
            line = line.strip()
            
            # OS detection results
            if 'Running:' in line or 'OS details:' in line:
                os_guess = line.split(':', 1)[1].strip()
                
            # Check for domain indicators
            if any(keyword in line.lower() for keyword in ['domain', 'workgroup', 'netbios']):
                domain_joined = True
        
        if os_guess or domain_joined is not None:
            return Target(
                host=target_host,
                os_guess=os_guess,
                domain_joined=domain_joined
            )
        
        return None


def create_adapter() -> NmapAdapter:
    """Create an nmap adapter instance."""
    return NmapAdapter()
