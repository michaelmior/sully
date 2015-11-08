import pytest

import ast
from sully import TaintAnalysis

# Below are simple objects we use for testing
# ==========

class Bar:
    def foo(self, tainted):
        x = tainted.baz()              # 2
        tainted.foo(x)                 # 3
        y = 3                          # 4
        return x                       # 5

# ==========

@pytest.fixture
def taint():
    return TaintAnalysis(Bar.foo, 'tainted')

def test_taint_var(taint):
    found_var = None
    for expr in taint.taint_exprs:
        if isinstance(expr, ast.Name) and expr.id == 'x':
            found_var = expr
            break
    assert found_var is not None
    assert isinstance(found_var.parent, ast.Assign)

    ancestors = found_var.ancestors()
    assert isinstance(ancestors[0], ast.Assign)
    assert isinstance(ancestors[1], ast.FunctionDef)
    assert isinstance(ancestors[2], ast.Module)

def test_notaint_var(taint):
    assert not any(isinstance(expr, ast.Name) and expr.id == 'y'
            for expr in taint.taint_exprs)

def test_taint_call(taint):
    assert any(isinstance(expr, ast.Call) and expr.lineno == 3
            for expr in taint.taint_exprs)
