import ast
from collections import defaultdict
import inspect
import itertools

# Get the source code of a function
def get_func_source(func):
    source = inspect.getsourcelines(func)[0]
    spaces = len(source[0]) - len(source[0].lstrip())
    source = [line[spaces:] for line in source if not line.isspace()]
    return ''.join(line for line in source if line[0] != '@')

# Produce the AST for the body of a function
def get_func_ast(func):
    source = get_func_source(func)
    return ast.parse(source).body[0].body

# Track parents of AST nodes
class ParentTransformer(ast.NodeTransformer):
    def visit(self, node, parent=None):
        # Ignore things which are not nodes
        if not isinstance(node, ast.AST):
            return

        # Recursively visit children
        for _, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    self.visit(item, node)
            else:
                self.visit(value, node)

        # Assign the parent and return the node
        node.parent = parent
        return node

# Traverse the AST to identify reads and writes to values
class TaintAnalysis(ast.NodeVisitor):
    def __init__(self, func, taint_obj=None):
        self.func = func
        if taint_obj is not None:
            self.taint_obj = ast.parse(taint_obj).body[0].value
        else:
            self.taint_obj = None
        super(TaintAnalysis, self).__init__()

        # Initialize lists to track usage
        self.read_lines = defaultdict(list)
        self.write_lines = defaultdict(list)
        self.taint_exprs = set()
        self.tainted_by = defaultdict(list)

        # Get the source code of the function and parse the AST
        source = get_func_source(func)
        func_ast = ast.parse(source)

        # Start visiting the root of the function's AST
        func_ast = ParentTransformer().visit(func_ast)
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

    # Check ant propagate taint if necessary
    def check_add_taint(self, source, target):
        if source in self.taint_exprs:
            self.tainted_by[target].extend(self.tainted_by[source][:])
            self.taint_exprs.add(target)

    # Initialize the taint information and then visit the node
    def visit(self, node):
        super(TaintAnalysis, self).visit(node)

    # Record a write to a given value
    def visit_Assign(self, node):
        self.visit(node.value)

        for target in node.targets:
            self.write_lines[self.get_id(target)].append(node.lineno)
            self.check_add_taint(node.value, target)

    # Copy the taint for comparison operators
    def visit_Compare(self, node):
        # XXX We only handle a single comparison
        if len(node.ops) != 1 or len(node.comparators) != 1:
            raise Exception()

        self.visit(node.left)
        self.check_add_taint(node.left, node)

        self.visit(node.comparators[0])
        self.check_add_taint(node.comparators[0], node)

    # Copy the taint for unary operators
    def visit_UnaryOp(self, node):
        self.visit(node.operand)
        self.check_add_taint(node.operand, node)

    # Copy the taint for boolean operators
    def visit_BoolOp(self, node):
        for value in node.values:
            self.visit(value)
            self.check_add_taint(value, node)


    # Copy the taint for binary operators
    def visit_BinOp(self, node):
        self.visit(node.left)
        self.check_add_taint(node.left, node)

        self.visit(node.right)
        self.check_add_taint(node.right, node)

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
        if isinstance(node.func, ast.Attribute):
            # Assume function calls on objects modify data
            self.write_lines[self.get_id(node.func.value)].append(node.lineno)

            # Record this node as one which introduces taint
            if nodes_equal(node.func.value, self.taint_obj):
                self.taint_exprs.add(node)

            if node.func.value.id == 'self':
                other_func = getattr(self.func.im_class, node.func.attr)
                other_args = inspect.getargspec(other_func).args[1:]
                ta = TaintAnalysis(other_func)

                # Check arguments which were read written
                # Note that we're being pessimistic for writes here since
                # assignments just "write" to the local variable for parameter
                # XXX Doesn't work for functions with starargs or kwargs
                for i, arg in enumerate(node.args):
                    if isinstance(arg, ast.Name):
                        arg_name = other_args[i]
                        if ta.read_lines.has_key(arg_name):
                            self.read_lines[arg.id].append(node.lineno)
                        if ta.write_lines.has_key(arg_name):
                            self.write_lines[arg.id].append(node.lineno)

                # Copy over attribute nodes which were read or written
                for var, _ in ta.read_lines.items():
                    if isinstance(var, tuple):
                        self.read_lines[var].append(node.lineno)

                for var, _ in ta.write_lines.items():
                    if isinstance(var, tuple):
                        self.write_lines[var].append(node.lineno)
        else:
            raise Exception()

        # Visit function parameters to record reads
        for arg in node.args:
            self.visit(arg)
        if node.starargs:
            self.visit(node.starargs)
        if node.kwargs:
            self.visit(node.kwargs)

# Check if two AST nodes are equal
def nodes_equal(node1, node2):
    if node1 is None or node2 is None:
        return False

    # Initialize iterators over both trees
    walk1 = ast.walk(node1)
    walk2 = ast.walk(node2)

    for node1, node2 in itertools.izip(walk1, walk2):
        # Check that there are the same number of fields
        if len(node1._fields) != len(node2._fields):
            return False

        # Check that all field values are equal
        for field1, field2 in itertools.izip(node1._fields, node2._fields):
            if field1 != field2:
                return False

            # Get the field values from each node
            value1 = getattr(node1, field1)
            value2 = getattr(node2, field2)

            # Recursively check all nodes
            if isinstance(value1, ast.AST) and isinstance(value2, ast.AST):
                if not nodes_equal(value1, value2):
                    return False
            elif value1 != value2:
                return False

    return True
