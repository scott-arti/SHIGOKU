
import yaml
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

@dataclass
class RecipeStep:
    id: str
    name: str
    action: str
    params: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)

@dataclass
class Recipe:
    name: str
    description: str
    agent: str
    steps: List[RecipeStep] = field(default_factory=list)
    trigger: Dict[str, Any] = field(default_factory=dict)
    raw_data: Dict[str, Any] = field(default_factory=dict)

class RecipeLoader:
    def __init__(self):
        self.recipes: Dict[str, Recipe] = {}

    def load_recipe(self, filepath: str) -> None:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            name = data.get("name", "unnamed_recipe")
            
            steps_data = data.get("steps", [])
            steps = []
            for i, s in enumerate(steps_data):
                steps.append(RecipeStep(
                    id=s.get("id", f"step_{i}"),
                    name=s.get("name", f"Step {i}"),
                    action=s.get("action", ""),
                    params=s.get("params", {}),
                    dependencies=s.get("dependencies", [])
                ))
            
            recipe = Recipe(
                name=name,
                description=data.get("description", ""),
                agent=data.get("agent", "universal"),
                trigger=data.get("trigger", {}),
                raw_data=data,
                steps=steps
            )
            
            self.recipes[name] = recipe
            logger.info("Loaded recipe: %s from %s", name, filepath)
            
        except Exception as e:
            logger.error("Failed to load recipe %s: %s", filepath, e)
            raise

    def match_recipes_to_context(self, context: Dict[str, Any]) -> List[Recipe]:
        """
        コンテキストにマッチするRecipeを検索。
        現状は全てのロード済みRecipeを返すか、名前が一致するものを返す。
        """
        return list(self.recipes.values())
