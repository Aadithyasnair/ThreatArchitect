from abc import ABC, abstractmethod
from typing import TypeVar, Generic, List, Optional, Any, Dict

T = TypeVar('T')

class IService(ABC):
    """Lifecycle service interface."""
    
    @abstractmethod
    def start(self) -> None:
        """Start the service."""
        pass
        
    @abstractmethod
    def stop(self) -> None:
        """Stop the service."""
        pass
        
    @abstractmethod
    def get_status(self) -> str:
        """Get the current service status."""
        pass


class IRepository(Generic[T], ABC):
    """Generic repository pattern interface for database storage."""
    
    @abstractmethod
    def get_by_id(self, entity_id: Any) -> Optional[T]:
        """Fetch entity by primary key."""
        pass
        
    @abstractmethod
    def get_all(self) -> List[T]:
        """Fetch all entities."""
        pass
        
    @abstractmethod
    def add(self, entity: T) -> None:
        """Add a new entity."""
        pass
        
    @abstractmethod
    def update(self, entity: T) -> None:
        """Update an existing entity."""
        pass
        
    @abstractmethod
    def delete(self, entity_id: Any) -> None:
        """Delete an entity by its key."""
        pass


class IWorker(ABC):
    """Interface for background thread tasks."""
    
    @abstractmethod
    def run(self) -> None:
        """Execute the worker task."""
        pass


class IPlugin(ABC):
    """Interface for plugins."""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Return the plugin name."""
        pass
        
    @abstractmethod
    def initialize(self, container: Any) -> None:
        """Initialize the plugin using the Service Container."""
        pass


class ITopologyRenderer:
    """Network canvas interface for drawing network topologies."""
    
    def render_node(self, node_id: str, label: str, node_type: str, x: float = 0, y: float = 0) -> None:
        """Add or update a node on the topology render."""
        pass
        
    def render_link(self, node_a: str, node_b: str, status: str = "active") -> None:
        """Draw link between two nodes."""
        pass
        
    def clear(self) -> None:
        """Clear the topology canvas."""
        pass


class IPacketCapture(IService):
    """Interface for packet capture functionality (Phase 2)."""
    
    @abstractmethod
    def start_capture(self, interface: str, filter_exp: Optional[str] = None) -> None:
        """Start capturing packets on a network interface."""
        pass
        
    @abstractmethod
    def stop_capture(self) -> None:
        """Stop packet capture."""
        pass


class ITrafficEmulator(IService):
    """Interface for network traffic emulation (Phase 2)."""
    
    @abstractmethod
    def generate_normal_traffic(self) -> None:
        """Simulate legitimate user traffic."""
        pass
        
    @abstractmethod
    def generate_suspicious_traffic(self) -> None:
        """Simulate scanning or multi-connection traffic."""
        pass
        
    @abstractmethod
    def generate_dangerous_traffic(self) -> None:
        """Simulate exploit or DDoS traffic."""
        pass


class IAnomalyDetector(ABC):
    """Interface for Deep Learning anomaly detection (Phase 3)."""
    
    @abstractmethod
    def detect_anomalies(self, features: Any) -> float:
        """Analyze standard network features and return anomaly score (0.0 to 1.0)."""
        pass


class IComplianceEvaluator(ABC):
    """Interface for security compliance evaluations (Phase 4)."""
    
    @abstractmethod
    def evaluate_framework(self, framework_name: str, network_state: Any) -> Dict[str, Any]:
        """Verify network layout and database metrics against standard compliance controls."""
        pass


class ILLMClient(ABC):
    """Interface for Local Ollama LLM requests."""
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if local LLM service is responsive."""
        pass
        
    @abstractmethod
    def generate_remediation(self, threat_model: Any) -> str:
        """Generate local deterministic remediation commands."""
        pass


class IReportGenerator(ABC):
    """Interface for PDF/HTML report generation (Phase 5)."""
    
    @abstractmethod
    def generate_compliance_report(self, results: Any, output_path: str) -> None:
        """Compile compliance checklist and findings into a printable format."""
        pass
