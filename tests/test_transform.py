import pytest

import ast
from sully import TaintAnalysis, block_including

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
