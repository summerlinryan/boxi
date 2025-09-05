"""
Port scanning stage for service discovery.

Uses nmap to discover open ports and services on target hosts.
"""

from typing import List

from boxi.adapters.nmap import create_adapter as create_nmap_adapter
from boxi.artifacts import Service, Target
from boxi.logging_config import StageLogger, log_artifact_found
from boxi.runtime import require_context


def run_port_scan(target: str) -> List[Service]:
    """
    Run port scan against target.
    
    Args:
        target: Target IP or hostname
        
    Returns:
        List of discovered services
    """
    context = require_context()
    
    with StageLogger("port_scan", target) as stage_log:
        # Create nmap adapter
        nmap = create_nmap_adapter()
        
        if not nmap.is_available():
            stage_log.warning("Nmap not available, skipping port scan")
            return []
        
        stage_log.info("Starting port scan")
        
        # Perform quick scan first
        services = nmap.quick_scan(target)
        
        if not services:
            stage_log.info("No services found in quick scan")
            return []
        
        stage_log.info(f"Quick scan found {len(services)} services")
        
        # Add services to context
        for service in services:
            context.add_service(service)
            log_artifact_found("service", f"{service.target_host}:{service.port}/{service.protocol}")
        
        # Try OS detection if we found open ports
        open_services = [s for s in services if s.state.value == "open"]
        if open_services:
            stage_log.info("Attempting OS detection")
            target_info = nmap.os_detection(target)
            
            if target_info:
                context.add_target(target_info)
                log_artifact_found("target", f"{target_info.host} ({target_info.os_guess})")
        
        stage_log.info(f"Port scan completed, found {len(services)} services")
        return services


def run_full_port_scan(target: str, ports: str = "1-65535") -> List[Service]:
    """
    Run comprehensive port scan against target.
    
    Args:
        target: Target IP or hostname
        ports: Port range to scan
        
    Returns:
        List of discovered services
    """
    context = require_context()
    
    with StageLogger("full_port_scan", target) as stage_log:
        nmap = create_nmap_adapter()
        
        if not nmap.is_available():
            stage_log.warning("Nmap not available, skipping full port scan")
            return []
        
        stage_log.info(f"Starting full port scan on {ports}")
        
        # Perform full scan with service detection
        services = nmap.full_scan(target, ports)
        
        if not services:
            stage_log.info("No additional services found in full scan")
            return []
        
        stage_log.info(f"Full scan found {len(services)} services")
        
        # Add new services to context
        for service in services:
            context.add_service(service)
            log_artifact_found("service", f"{service.target_host}:{service.port}/{service.protocol}")
        
        return services


def run_udp_scan(target: str, top_ports: int = 100) -> List[Service]:
    """
    Run UDP port scan against target.
    
    Args:
        target: Target IP or hostname
        top_ports: Number of top UDP ports to scan
        
    Returns:
        List of discovered UDP services
    """
    context = require_context()
    
    with StageLogger("udp_scan", target) as stage_log:
        nmap = create_nmap_adapter()
        
        if not nmap.is_available():
            stage_log.warning("Nmap not available, skipping UDP scan")
            return []
        
        stage_log.info(f"Starting UDP scan on top {top_ports} ports")
        
        # Perform UDP scan
        services = nmap.udp_scan(target, top_ports)
        
        if not services:
            stage_log.info("No UDP services found")
            return []
        
        stage_log.info(f"UDP scan found {len(services)} services")
        
        # Add services to context
        for service in services:
            context.add_service(service)
            log_artifact_found("service", f"{service.target_host}:{service.port}/{service.protocol}")
        
        return services


def check_stage_requirements() -> bool:
    """Check if this stage can run (nmap available)."""
    nmap = create_nmap_adapter()
    return nmap.is_available()


def get_stage_info() -> dict:
    """Get information about this stage."""
    return {
        "name": "port_scan",
        "description": "Discover open ports and services using nmap",
        "requirements": ["nmap"],
        "produces": ["Service", "Target"],
        "safe": True,
    }
