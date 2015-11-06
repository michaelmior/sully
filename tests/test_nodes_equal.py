import ast

from sully import nodes_equal

# Helper function to get the AST from an expression
def parse_source(source):
    return ast.parse(source).body[0].value

def test_names_equal():
    assert nodes_equal(ast.Name(id='foo', ctx=ast.Load()),
                       ast.Name(id='foo', ctx=ast.Load()))

def test_names_unequal():
    assert not nodes_equal(ast.Name(id='foo', ctx=ast.Load()),
                           ast.Name(id='bar', ctx=ast.Load()))

def test_attribute_equal():
    assert nodes_equal(parse_source('self.x'), parse_source('self.x'))

def test_attribute_unequal():
    assert not nodes_equal(parse_source('self.x'), parse_source('self.y'))

def test_subscript_equal():
    assert nodes_equal(parse_source('x[0]'), parse_source('x[0]'))

def test_subscript_unequal():
    assert not nodes_equal(parse_source('x[0]'), parse_source('x[1]'))
