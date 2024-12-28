import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class PluginRegistry:
    """A class that serves as a central place to register and load plugins.

    Plugins that are derived from a base class are stored in that base class's registry.
    """

    _registry_map = dict()

    def __init__(self):
        self._subclasses = dict()

    @classmethod
    def load_plugins(cls, path: str) -> None:
        """Loads plugins from all modules under the given path.

        :param path: The path to load plugins from.
        """
        project_base = "acmetk"
        import sys

        try:
            module_base_name = f"{project_base}.{path}"
            __import__(module_base_name)
            o = sys.modules[module_base_name]
            path_ = Path(o.__file__).parent
            for i in path_.iterdir():
                module_name = f"{module_base_name}.{i.stem}"
                logger.debug("Loading %s", module_name)
                try:
                    __import__(module_name)
                except Exception as e:
                    logger.info("… failed %s", str(e))

        except FileNotFoundError:
            logger.warning(
                "Could not find the plugins directory in ./%s/%s or ./%s",
                project_base,
                path,
                path,
            )

    @classmethod
    def get_registry(cls, plugin_parent_cls: type) -> "PluginRegistry":
        """Gets the plugin registry for the given parent class.

        :param plugin_parent_cls: The parent class.
        :return: The plugin registry for the given parent class.
        """
        registry = cls._registry_map.setdefault(plugin_parent_cls, PluginRegistry())
        return registry

    @classmethod
    def register_plugin(cls, config_name):
        """Decorator that registers a class as a plugin under the given name.
        The name is used to refer to the class in config files.

        :param config_name: The plugin's name in config files
        :return: The registered plugin class.
        """

        def deco(plugin_cls):
            # find the parent class in the registry map
            for registered_parent, registry_ in cls._registry_map.items():
                if issubclass(plugin_cls, registered_parent):
                    registry = registry_
                    break
            else:
                registry = cls.get_registry(plugin_cls.__mro__[1])

            registry._subclasses[config_name] = plugin_cls

            return plugin_cls

        return deco

    def config_mapping(self) -> dict[str, type]:
        """Method that maps plugin config names to the actual class object.

        :return: Mapping from config names to the actual class objects.
        """
        return self._subclasses

    def get_plugin(self, config_name) -> type:
        """Queries the registry for a plugin by config name.

        :param config_name: The plugin's config name
        :raises: :class:`ValueError` If no plugin is registered by the given name
        :return: The found plugin class
        """
        if config_name not in (plugin_names := self._subclasses.keys()):
            raise ValueError(
                f"The plugin {config_name} has not been registered. Valid options: "
                f"{', '.join([plugin for plugin in plugin_names])}."
            )

        return self._subclasses[config_name]
