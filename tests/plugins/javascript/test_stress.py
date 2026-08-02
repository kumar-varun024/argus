import pytest
from argus.plugins.javascript.parser import JavaScriptParser

def test_stress_parser_deeply_nested():
    parser = JavaScriptParser()
    
    # Deeply nested scopes to ensure regex doesn't trigger catastrophic backtracking
    nested_braces = "{" * 1000 + "}" * 1000
    nested_brackets = "[" * 1000 + "]" * 1000
    
    content = f"const a = {nested_braces}; const b = {nested_brackets};"
    
    # Should complete without timing out or raising recursion errors
    ast_nodes, modules, symbols, routes, frameworks, websockets = parser.parse(content, "stress.js")
    assert len(symbols) == 3 # 'a' as Constant, 'b' as Constant, 'a' as Object

def test_stress_parser_long_strings():
    parser = JavaScriptParser()
    
    # Massive strings with no matches
    long_string = "a" * 1000000
    
    # Should complete instantly
    ast_nodes, modules, symbols, routes, frameworks, websockets = parser.parse(long_string, "stress.js")
    assert len(symbols) == 0
