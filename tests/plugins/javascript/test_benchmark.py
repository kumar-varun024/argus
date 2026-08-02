import time
from argus.plugins.javascript.parser import JavaScriptParser

def test_benchmark_parser():
    parser = JavaScriptParser()
    
    # Generate a large fake JS bundle (approx 1MB)
    base_snippet = """
    function handleClick() {
        console.log('Clicked');
        axios.post('https://api.example.com/v1/event', { type: 'click' });
    }
    const configOptions = { url: 'http://test' };
    const ENABLE_FEATURE_X = true;
    import { something } from 'moduleA';
    """
    
    # Multiply to simulate a large bundle
    large_bundle = base_snippet * 5000 
    
    start_time = time.time()
    ast_nodes, modules, symbols, routes, frameworks, websockets = parser.parse(large_bundle, "large_bundle.js")
    end_time = time.time()
    
    duration = end_time - start_time
    
    # With caching and inline deduplication, this should parse reasonably fast (under 1 second ideally)
    assert duration < 5.0, f"Parser took too long: {duration}s"
    
    # Assert things were found
    assert len(symbols) > 0
    assert len(modules) > 0
