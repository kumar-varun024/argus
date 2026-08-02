import pytest
from argus.plugins.javascript.parser import JavaScriptParser

def test_javascript_parser():
    parser = JavaScriptParser()
    
    js_content = """
    import { something } from 'moduleA';
    require('moduleB');
    
    const NEXT_PUBLIC_API_URL = "https://api.example.com";
    const ENABLE_NEW_FEATURE = true;
    
    class MyClass {
        constructor() {}
    }
    
    function myFunction(a, b) {
        return a + b;
    }
    
    const myArrow = (x) => x * 2;
    
    export const exportedConst = 42;
    export default MyClass;
    
    const myObject = { a: 1 };
    
    const appConfig = { url: "http://test" };
    export const serverOptions = { port: 8080 };
    """
    
    ast_nodes, modules, symbols, routes, frameworks, websockets = parser.parse(js_content, "source.js")
    
    # Check Modules
    assert len(modules) == 1
    assert modules[0].module_type == "ES Modules"
    assert "moduleA" in modules[0].imports
    assert "moduleB" in modules[0].imports
    
    # Check AST Nodes
    node_types = [n.node_type for n in ast_nodes]
    assert "ClassDeclaration" in node_types
    assert "FunctionDeclaration" in node_types
    
    # Check Symbols
    symbol_names = [s.name for s in symbols]
    assert "moduleA" in symbol_names # from import
    assert "moduleB" in symbol_names # from require
    assert "NEXT_PUBLIC_API_URL" in symbol_names # EnvVar
    assert "ENABLE_NEW_FEATURE" in symbol_names # FeatureFlag
    assert "MyClass" in symbol_names # Class and Export Default
    assert "myFunction" in symbol_names # Function
    assert "myArrow" in symbol_names # Function
    assert "exportedConst" in symbol_names # Export
    assert "myObject" in symbol_names # Object
    assert "appConfig" in symbol_names # Configuration
    assert "serverOptions" in symbol_names # Configuration
    
    symbol_dict = {}
    for s in symbols:
        symbol_dict.setdefault(s.name, []).append(s.symbol_type)
        
    assert "EnvVar" in symbol_dict["NEXT_PUBLIC_API_URL"]
    assert "FeatureFlag" in symbol_dict["ENABLE_NEW_FEATURE"]
    assert "Class" in symbol_dict["MyClass"]
    assert "Function" in symbol_dict["myFunction"]
    assert "Export" in symbol_dict["exportedConst"]
    assert "Object" in symbol_dict["myObject"]
    assert "Configuration" in symbol_dict["appConfig"]
    assert "Configuration" in symbol_dict["serverOptions"]

def test_javascript_parser_framework_detection():
    parser = JavaScriptParser()
    
    # Webpack
    _, m1, _, _, _, _ = parser.parse("(window.webpackJsonp = window.webpackJsonp || []).push()", "a.js")
    assert m1[0].module_type == "Webpack bundles"
    
    # Next.js
    _, m2, _, _, _, _ = parser.parse("window.__NEXT_DATA__ = {}", "b.js")
    assert m2[0].module_type == "Next.js"
    
    # Vite
    _, m3, _, _, _, _ = parser.parse("const modules = import.meta.glob('./dir/*.js')", "c.js")
    assert m3[0].module_type == "Vite"
    
    # Rollup
    _, m4, _, _, _, _ = parser.parse("System.register(['./utils.js'], function (exports, module) {", "d.js")
    assert m4[0].module_type == "Rollup"
    
    # CommonJS
    _, m5, _, _, _, _ = parser.parse("const path = require('path');", "e.js")
    assert m5[0].module_type == "CommonJS"

def test_javascript_parser_pr4_features():
    parser = JavaScriptParser()
    
    js_content = """
    import React from 'react';
    import { useNavigate } from 'react-router-dom';
    
    const ws = new WebSocket('wss://api.example.com/stream');
    
    function App() {
        const navigate = useNavigate();
        const goToProfile = () => {
            navigate('/profile');
        }
        
        return (
            <div>
                <Route path='/users/:id' />
                <Link to='/home'>Home</Link>
            </div>
        )
    }
    """
    
    ast_nodes, modules, symbols, routes, frameworks, websockets = parser.parse(js_content, "react_app.js")
    
    # Frameworks
    fw_names = [f.name for f in frameworks]
    assert "React" in fw_names
    
    # Routes
    route_paths = [r.path for r in routes]
    assert "/users/:id" in route_paths
    assert "/home" in route_paths
    assert "/profile" in route_paths
    
    # Websockets
    ws_urls = [w.url for w in websockets]
    assert "wss://api.example.com/stream" in ws_urls

def test_javascript_parser_pr5_features():
    parser = JavaScriptParser()
    
    js_content = """
    import { ApolloClient } from '@apollo/client';
    import { Auth0Provider } from '@auth0/auth0-react';
    import * as grpc from '@grpc/grpc-js';
    
    interface UserProfile {
        id: string;
        name: string;
    }
    
    const signInWithGoogle = () => {};
    
    function submitOrder() {
        return axios.post('https://api.stripe.com/v1/charges', {});
    }
    """
    
    ast_nodes, modules, symbols, routes, frameworks, websockets = parser.parse(js_content, "app.js")
    
    symbol_dict = {}
    for s in symbols:
        symbol_dict.setdefault(s.symbol_type, []).append(s.name)
        
    assert "GraphQLEndpoint" in symbol_dict
    assert "gRPCReference" in symbol_dict
    assert "https://api.stripe.com" in symbol_dict.get("ThirdPartyAPI", [])
    assert "Auth0" in symbol_dict.get("AuthProvider", [])
    assert "signInWithGoogle" in symbol_dict.get("OAuthProvider", [])
    assert "UserProfile" in symbol_dict.get("Object", [])
    assert "submitOrder" in symbol_dict.get("BusinessWorkflow", [])
    assert "https://api.stripe.com/v1/charges" in symbol_dict.get("RESTEndpoint", [])
