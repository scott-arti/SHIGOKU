"""
Dependency Injection Container for SHIGOKU
Elegant, type-safe DI with async support
"""
from __future__ import annotations
import asyncio
from typing import TypeVar, Type, Dict, Any, Callable, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass(frozen=True)
class ServiceKey:
    """Immutable service identifier"""
    interface: Type
    name: Optional[str] = None
    
    def __hash__(self) -> int:
        return hash((self.interface, self.name))
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ServiceKey):
            return False
        return self.interface == other.interface and self.name == other.name


class DIContainer:
    """
    Elegant DI Container with:
    - Singleton and transient lifetimes
    - Async factory support
    - Type-safe resolution
    - Circular dependency detection
    """
    
    def __init__(self):
        self._registrations: Dict[ServiceKey, Callable[..., T]] = {}
        self._singletons: Dict[ServiceKey, Any] = {}
        self._resolution_stack: set = set()
    
    def register_singleton(
        self, 
        interface: Type[T], 
        factory: Callable[..., T], 
        name: Optional[str] = None
    ) -> DIContainer:
        """Register a singleton service"""
        key = ServiceKey(interface, name)
        self._registrations[key] = factory
        return self
    
    def register_transient(
        self, 
        interface: Type[T], 
        factory: Callable[..., T], 
        name: Optional[str] = None
    ) -> DIContainer:
        """Register a transient (per-request) service"""
        key = ServiceKey(interface, name)
        self._registrations[key] = factory
        return self
    
    def register_instance(
        self, 
        interface: Type[T], 
        instance: T, 
        name: Optional[str] = None
    ) -> DIContainer:
        """Register a pre-created instance"""
        key = ServiceKey(interface, name)
        self._singletons[key] = instance
        return self
    
    async def resolve(
        self, 
        interface: Type[T], 
        name: Optional[str] = None
    ) -> T:
        """
        Resolve a service by interface
        
        Raises:
            KeyError: If service not registered
            RuntimeError: On circular dependency
        """
        key = ServiceKey(interface, name)
        
        # Circular dependency detection
        if key in self._resolution_stack:
            raise RuntimeError(f"Circular dependency detected: {key}")
        
        # Return existing singleton
        if key in self._singletons:
            return self._singletons[key]
        
        # Create new instance
        if key not in self._registrations:
            raise KeyError(f"Service not registered: {key}")
        
        factory = self._registrations[key]
        
        self._resolution_stack.add(key)
        try:
            # Support both sync and async factories
            if asyncio.iscoroutinefunction(factory):
                instance = await factory(self)
            else:
                instance = factory(self)
            
            # Cache as singleton
            self._singletons[key] = instance
            return instance
        finally:
            self._resolution_stack.discard(key)
    
    def is_registered(self, interface: Type, name: Optional[str] = None) -> bool:
        """Check if service is registered"""
        key = ServiceKey(interface, name)
        return key in self._registrations or key in self._singletons
    
    def create_scope(self) -> DIScope:
        """Create a child scope for request isolation"""
        return DIScope(self)


class DIScope:
    """
    Request-scoped DI container
    For transient services and request isolation
    """
    
    def __init__(self, parent: DIContainer):
        self._parent = parent
        self._transients: Dict[ServiceKey, Any] = {}
    
    async def resolve(
        self, 
        interface: Type[T], 
        name: Optional[str] = None
    ) -> T:
        """Resolve service within scope"""
        key = ServiceKey(interface, name)
        
        # Return cached transient
        if key in self._transients:
            return self._transients[key]
        
        # Resolve from parent
        instance = await self._parent.resolve(interface, name)
        
        # Cache as transient in scope
        self._transients[key] = instance
        return instance
    
    def dispose(self):
        """Clean up scoped resources"""
        self._transients.clear()


# Global container instance
_container: Optional[DIContainer] = None


def get_container() -> DIContainer:
    """Get or create global DI container"""
    global _container
    if _container is None:
        _container = DIContainer()
    return _container


def reset_container():
    """Reset global container (for testing)"""
    global _container
    _container = None
