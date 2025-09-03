"""
Dependency Injection Container
Professional IoC container for managing component dependencies
"""

import inspect
import threading
from abc import ABC, abstractmethod
from typing import Any, Dict, Type, TypeVar, Generic, Optional, Callable, Union
from dataclasses import dataclass
from enum import Enum


T = TypeVar('T')


class Scope(Enum):
    """Dependency injection scopes"""
    SINGLETON = "singleton"
    TRANSIENT = "transient"
    SCOPED = "scoped"


@dataclass
class ServiceDescriptor:
    """Service registration descriptor"""
    service_type: Type
    implementation_type: Optional[Type] = None
    factory: Optional[Callable] = None
    instance: Optional[Any] = None
    scope: Scope = Scope.TRANSIENT
    dependencies: Optional[Dict[str, Type]] = None


class DIContainer:
    """Professional Dependency Injection Container"""
    
    def __init__(self):
        self._services: Dict[Type, ServiceDescriptor] = {}
        self._instances: Dict[Type, Any] = {}
        self._scoped_instances: Dict[str, Dict[Type, Any]] = {}
        self._lock = threading.RLock()
        self._current_scope: Optional[str] = None
    
    def register_singleton(self, service_type: Type[T], implementation_type: Optional[Type[T]] = None, 
                          factory: Optional[Callable[[], T]] = None) -> 'DIContainer':
        """Register a singleton service"""
        return self._register(service_type, implementation_type, factory, Scope.SINGLETON)
    
    def register_transient(self, service_type: Type[T], implementation_type: Optional[Type[T]] = None,
                          factory: Optional[Callable[[], T]] = None) -> 'DIContainer':
        """Register a transient service"""
        return self._register(service_type, implementation_type, factory, Scope.TRANSIENT)
    
    def register_scoped(self, service_type: Type[T], implementation_type: Optional[Type[T]] = None,
                       factory: Optional[Callable[[], T]] = None) -> 'DIContainer':
        """Register a scoped service"""
        return self._register(service_type, implementation_type, factory, Scope.SCOPED)
    
    def register_instance(self, service_type: Type[T], instance: T) -> 'DIContainer':
        """Register a specific instance"""
        with self._lock:
            descriptor = ServiceDescriptor(
                service_type=service_type,
                instance=instance,
                scope=Scope.SINGLETON
            )
            self._services[service_type] = descriptor
            self._instances[service_type] = instance
        return self
    
    def _register(self, service_type: Type[T], implementation_type: Optional[Type[T]], 
                 factory: Optional[Callable], scope: Scope) -> 'DIContainer':
        """Internal registration method"""
        with self._lock:
            # Analyze dependencies
            dependencies = None
            target_type = implementation_type or service_type
            
            if hasattr(target_type, '__init__'):
                sig = inspect.signature(target_type.__init__)
                dependencies = {}
                for param_name, param in sig.parameters.items():
                    if param_name != 'self' and param.annotation != inspect.Parameter.empty:
                        dependencies[param_name] = param.annotation
            
            descriptor = ServiceDescriptor(
                service_type=service_type,
                implementation_type=implementation_type,
                factory=factory,
                scope=scope,
                dependencies=dependencies
            )
            
            self._services[service_type] = descriptor
        return self
    
    def resolve(self, service_type: Type[T]) -> T:
        """Resolve a service instance"""
        with self._lock:
            return self._resolve_internal(service_type, set())
    
    def _resolve_internal(self, service_type: Type[T], resolving: set) -> T:
        """Internal resolution with circular dependency detection"""
        if service_type in resolving:
            raise ValueError(f"Circular dependency detected: {service_type}")
        
        if service_type not in self._services:
            raise ValueError(f"Service {service_type} not registered")
        
        descriptor = self._services[service_type]
        
        # Check existing instances based on scope
        if descriptor.scope == Scope.SINGLETON:
            if service_type in self._instances:
                return self._instances[service_type]
        elif descriptor.scope == Scope.SCOPED and self._current_scope:
            scoped_instances = self._scoped_instances.get(self._current_scope, {})
            if service_type in scoped_instances:
                return scoped_instances[service_type]
        
        # Create new instance
        resolving.add(service_type)
        try:
            instance = self._create_instance(descriptor, resolving)
        finally:
            resolving.remove(service_type)
        
        # Store instance based on scope
        if descriptor.scope == Scope.SINGLETON:
            self._instances[service_type] = instance
        elif descriptor.scope == Scope.SCOPED and self._current_scope:
            if self._current_scope not in self._scoped_instances:
                self._scoped_instances[self._current_scope] = {}
            self._scoped_instances[self._current_scope][service_type] = instance
        
        return instance
    
    def _create_instance(self, descriptor: ServiceDescriptor, resolving: set) -> Any:
        """Create a new instance of the service"""
        # Use existing instance
        if descriptor.instance is not None:
            return descriptor.instance
        
        # Use factory
        if descriptor.factory is not None:
            return descriptor.factory()
        
        # Use implementation type or service type
        target_type = descriptor.implementation_type or descriptor.service_type
        
        # Resolve dependencies
        kwargs = {}
        if descriptor.dependencies:
            for param_name, param_type in descriptor.dependencies.items():
                kwargs[param_name] = self._resolve_internal(param_type, resolving)
        
        return target_type(**kwargs)
    
    def create_scope(self, scope_name: str) -> 'DIScope':
        """Create a new dependency injection scope"""
        return DIScope(self, scope_name)
    
    def _enter_scope(self, scope_name: str):
        """Enter a scope (internal)"""
        self._current_scope = scope_name
        if scope_name not in self._scoped_instances:
            self._scoped_instances[scope_name] = {}
    
    def _exit_scope(self, scope_name: str):
        """Exit a scope (internal)"""
        if scope_name in self._scoped_instances:
            # Dispose scoped instances
            for instance in self._scoped_instances[scope_name].values():
                if hasattr(instance, 'dispose'):
                    try:
                        instance.dispose()
                    except Exception:
                        pass  # Ignore disposal errors
            del self._scoped_instances[scope_name]
        self._current_scope = None
    
    def is_registered(self, service_type: Type) -> bool:
        """Check if a service is registered"""
        return service_type in self._services
    
    def get_registrations(self) -> Dict[Type, ServiceDescriptor]:
        """Get all service registrations"""
        return self._services.copy()


class DIScope:
    """Dependency injection scope context manager"""
    
    def __init__(self, container: DIContainer, scope_name: str):
        self.container = container
        self.scope_name = scope_name
    
    def __enter__(self):
        self.container._enter_scope(self.scope_name)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.container._exit_scope(self.scope_name)


class Injectable:
    """Base class for injectable services"""
    
    def dispose(self):
        """Override to provide cleanup logic"""
        pass


# Global container instance
_container = DIContainer()


def get_container() -> DIContainer:
    """Get the global DI container"""
    return _container


def inject(service_type: Type[T]) -> T:
    """Shorthand for resolving a service"""
    return _container.resolve(service_type)


def configure_services(configurator: Callable[[DIContainer], None]):
    """Configure services using a configurator function"""
    configurator(_container)


# Decorators for automatic registration
def singleton(cls: Type[T]) -> Type[T]:
    """Decorator to register a class as singleton"""
    _container.register_singleton(cls, cls)
    return cls


def transient(cls: Type[T]) -> Type[T]:
    """Decorator to register a class as transient"""
    _container.register_transient(cls, cls)
    return cls


def scoped(cls: Type[T]) -> Type[T]:
    """Decorator to register a class as scoped"""
    _container.register_scoped(cls, cls)
    return cls
