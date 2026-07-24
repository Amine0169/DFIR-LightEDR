import os
import yaml
import logging
from pathlib import Path
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class SigmaEngine:
    def __init__(self, rules_path: str):
        self.rules_path = rules_path
        self.rules = []
        self.load_rules()

    def load_rules(self) -> List[Dict[str, Any]]:
        path = Path(self.rules_path)
        if not path.exists() or not path.is_dir():
            logger.warning(f"Sigma rules path not found: {self.rules_path}")
            return self.rules

        for filepath in path.rglob('*.yml'):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    # Some files might contain multiple yaml documents
                    docs = yaml.safe_load_all(f)
                    for doc in docs:
                        if doc and 'title' in doc and 'detection' in doc:
                            self.rules.append(doc)
            except Exception as e:
                logger.error(f"Error loading Sigma rule {filepath}: {e}")
                
        logger.info(f"Loaded {len(self.rules)} Sigma rules.")
        return self.rules

    def evaluate_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        matches = []
        for rule in self.rules:
            try:
                if self._match_detection(event, rule.get('detection', {})):
                    matches.append({
                        "title": rule.get('title'),
                        "id": rule.get('id'),
                        "level": rule.get('level', 'medium'),
                        "description": rule.get('description', ''),
                        "tags": rule.get('tags', []),
                        "mitre_tags": [tag for tag in rule.get('tags', []) if tag.startswith('attack.')]
                    })
            except Exception as e:
                logger.debug(f"Error evaluating rule {rule.get('title')}: {e}")
        return matches

    def _match_detection(self, event: Dict[str, Any], detection: Dict[str, Any]) -> bool:
        condition = detection.get('condition', '')
        if not condition:
            return False
            
        # Simplified condition evaluation
        # Real Sigma eval involves a parser, but we handle basic 'selection' and 'selection1 or selection2'
        
        # If the condition just specifies a selection name
        if condition in detection and condition != 'condition':
            return self._match_selection(event, detection[condition])
            
        # If it's something like "selection"
        if condition == 'selection' and 'selection' in detection:
            return self._match_selection(event, detection['selection'])
            
        # VERY basic parsing for generic "x or y"
        parts = condition.split(' ')
        if 'or' in parts:
            for part in parts:
                if part in detection and part != 'condition':
                    if self._match_selection(event, detection[part]):
                        return True
            return False
            
        if 'and' in parts:
            for part in parts:
                if part in detection and part != 'condition':
                    if not self._match_selection(event, detection[part]):
                        return False
            return True

        # Fallback to evaluating all selections with logical OR
        for key, value in detection.items():
            if key != 'condition':
                if self._match_selection(event, value):
                    return True
                    
        return False

    def _match_selection(self, event: Dict[str, Any], selection: Any) -> bool:
        if isinstance(selection, dict):
            for k, v in selection.items():
                # Handle modifiers like EventID|endswith
                key_parts = k.split('|')
                field = key_parts[0]
                modifier = key_parts[1] if len(key_parts) > 1 else 'equals'
                
                if field not in event:
                    return False
                    
                event_val = str(event[field]).lower()
                
                if isinstance(v, list):
                    matched_any = False
                    for item in v:
                        if self._compare(event_val, str(item).lower(), modifier):
                            matched_any = True
                            break
                    if not matched_any:
                        return False
                else:
                    target_val = str(v).lower()
                    if not self._compare(event_val, target_val, modifier):
                        return False
            return True
        elif isinstance(selection, list):
            # A list of maps, evaluated as logical OR
            for item in selection:
                if self._match_selection(event, item):
                    return True
            return False
            
        return False
        
    def _compare(self, actual: str, target: str, modifier: str) -> bool:
        if modifier == 'equals':
            return actual == target
        elif modifier == 'contains':
            return target in actual
        elif modifier == 'startswith':
            return actual.startswith(target)
        elif modifier == 'endswith':
            return actual.endswith(target)
        return actual == target

    def get_loaded_rules_count(self) -> int:
        return len(self.rules)
