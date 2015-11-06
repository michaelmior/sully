import ast
from collections import defaultdict
import inspect

# Traverse the AST to identify reads and writes to values
class TaintAnalysis(ast.NodeVisitor):
    def __init__(self, func):
        super(TaintAnalysis, self).__init__()

        # Initialize lists to track usage
        self.read_lines = defaultdict(list)
        self.write_lines = defaultdict(list)

        # Get the source code of the function and parse the AST
        source = inspect.getsourcelines(func)[0]
        spaces = len(source[0]) - len(source[0].lstrip())
        source = [line[spaces:] for line in source if not line.isspace()]
        source = ''.join(line for line in source if line[0] != '@')
        func_ast = ast.parse(source)

        # Start visiting the root of the function's AST
        self.visit(func_ast)

    # Get the identifier to use when recording a read/write
    def get_id(self, node):
        if isinstance(node, ast.Name):
            # Simple variables get recorded by name
            return node.id
        elif isinstance(node, ast.Attribute):
            # We don't track writes to anything not on `self`
            if node.value.id == 'self':
                return ('self', node.attr)
            else:
                raise Exception()
        elif isinstance(node, ast.Subscript):
            # Record array writes as a write to the whole array
            return self.get_id(node.value)
        else:
            # XXX Debugging for things we don't support
            print(ast.dump(node))
            print(node._fields)
            raise Exception()

    # TODO Detect modification via .append(...) and .insert(...)
    #      and helper function calls

    # Record a write to a given value
    def visit_Assign(self, node):
        for target in node.targets:
            self.write_lines[self.get_id(target)].append(node.lineno)

    # Record a read of an attribute on some value
    def visit_Attribute(self, node):
        var = (self.get_id(node.value), node.attr)
        self.read_lines[var].append(node.lineno)

    # Record a read of a simple variable
    def visit_Name(self, node):
        # This ignores parameter names and references to self since
        # we will capture these when we visit Attribute nodes
        if isinstance(node.ctx, ast.Load) and node.id != 'self':
            self.read_lines[node.id].append(node.lineno)

    # Record reads and writes from functions called within our function
    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            if node.func.id == 'self':
                # TODO Handle calls to helper functions
                pass

            raise Exception()
        elif isinstance(node.func, ast.Attribute):
            # Assume function calls on objects modify data
            self.write_lines[self.get_id(node.func.value)].append(node.lineno)

        # Visit function parameters to record reads
        for arg in node.args:
            self.visit(arg)
        if node.starargs:
            self.visit(node.starargs)
        if node.kwargs:
            self.visit(node.kwargs)

# Simple wrapper for the TaintAnalysis visitor given a function
def taint(func):
    # Perform the analysis
    ta = TaintAnalysis(func)
    return ta
