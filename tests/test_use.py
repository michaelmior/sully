import pytest

from sully import taint

# Below are simple objects we use for testing
# ==========

class constants:
    BAZ = 7

class Bar:
    x = 2
    y = [4, 5, 6]

    def foo(self):                    # 1
        y = [1, 2, 3]                 # 2
        x = 3 + y[1]                  # 3
        y[3] += 2 + self.x            # 4
        self.x = y[0]                 # 5
        self.y[1] = y[0]              # 6
        self.x = y[0]                 # 7
        return x + 2 + constants.BAZ  # 8

# ==========

@pytest.fixture
def ta():
    return taint(Bar.foo)

def test_simple_read(ta):
    assert ta.read_lines['x'] == [8]

def test_simple_write(ta):
    assert ta.write_lines['x'] == [3]

def test_self_read(ta):
    assert ta.read_lines[('self', 'x')] == [4]

def test_self_write(ta):
    assert ta.write_lines[('self', 'x')] == [5, 7]

def test_constant_read(ta):
    assert ta.read_lines[('constants', 'BAZ')] == [8]

def test_array_read(ta):
    assert ta.read_lines['y'] == [4]

def test_array_write(ta):
    assert ta.write_lines['y'] == [2]
