import pytest

from sully import TaintAnalysis, block_inout

# Below are simple objects we use for testing
# ==========

class constants:
    BAZ = 7

class Bar:
    x = 2
    y = [4, 5, 6]

    def helper2(self):
        return self.b

    def helper(self, x):
        x.append(2)
        self.a = 3
        return self.z + self.helper2()

    def foo(self):                    # 1
        y = [1, 2, 3]                 # 2
        x = 3 + y[1]                  # 3
        y[3] += 2 + self.x            # 4
        self.x = y[0]                 # 5
        self.y[1] = y[0]              # 6
        self.x = y[0]                 # 7
        x + 2 + constants.BAZ         # 8
        z = []                        # 9
        z.append(3)                   # 10
        a = []                        # 11
        b = []                        # 12
        c = {}                        # 13
        self.helper(a, *b, **c)       # 14

# ==========

@pytest.fixture
def taint():
    return TaintAnalysis(Bar.foo)

def test_helper_track(taint):
    assert taint.functions[('self', 'helper')] == set([14])

def test_function_write(taint):
    assert taint.write_lines['z'] == set([9, 10])

def test_simple_read(taint):
    assert taint.read_lines['x'] == set([8])

def test_simple_write(taint):
    assert taint.write_lines['x'] == set([3])

def test_self_read(taint):
    assert taint.read_lines[('self', 'x')] == set([4])

def test_self_write(taint):
    assert taint.write_lines[('self', 'x')] == set([5, 7])

def test_constaint(taint):
    assert taint.read_lines[('constants', 'BAZ')] == set([8])

def test_array_read(taint):
    assert taint.read_lines['y'] == set([3, 4, 5, 6, 7])

def test_array_write(taint):
    assert taint.write_lines['y'] == set([2])

def test_parameter_read(taint):
    assert taint.read_lines['a'] == set([14])
    assert taint.read_lines['b'] == set([14])
    assert taint.read_lines['c'] == set([14])

def test_helper_read(taint):
    assert taint.read_lines[('self', 'z')] == set([14])

def test_helper_write(taint):
    assert taint.write_lines[('self', 'a')] == set([14])

def test_helper_parameter_write(taint):
    assert taint.write_lines['a'] == set([11, 14])

def test_helper_inout(taint):
    in_exprs, out_exprs = block_inout(taint.func, 14, 14)
    assert ('self', 'z') in in_exprs
    assert ('self', 'b') in in_exprs
    assert ('self', 'a') in out_exprs
