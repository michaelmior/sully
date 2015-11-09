import pytest

import ast
from sully import TaintAnalysis, block_including, block_inout

# Below are simple objects we use for testing
# ==========

def foo():
    x = [1, 2, 3]                       # 2
    for y in x:                         # 3
        print(y)                        # 4
        x.append(y + 1)                 # 5
        break                           # 6

# ==========

@pytest.fixture
def taint():
    return TaintAnalysis(foo)

def test_linenos(taint):
    # Find the for node
    for_node = None
    for node in ast.walk(taint.func_ast):
        if isinstance(node, ast.For):
            for_node = node
            break

    assert for_node is not None
    assert for_node.minlineno == 3
    assert for_node.maxlineno == 6

def test_block(taint):
    block = block_including(taint.func_ast, 5, 6)
    assert len(block) == 1
    assert isinstance(block[0], ast.For)

def test_block_list(taint):
    block = block_including(taint.func_ast.body[0].body, 5, 6)
    assert len(block) == 1
    assert isinstance(block[0], ast.For)

def test_block_inout(taint):
    in_exprs, out_exprs = block_inout(taint.func_ast, 3, 6)
    assert in_exprs == set(['x', 'y'])
    assert out_exprs == set(['x'])
