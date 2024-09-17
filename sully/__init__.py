import ast
from collections import defaultdict
import inspect
import itertools

# Get the source code of a function
def get_func_source(func):
    source = inspect.getsourcelines(func)[0]
    spaces = len(source[0]) - len(source[0].lstrip())
    source = [line[spaces:] for line in source]

    # Skip lines starting wtih @ and make empty lines into comments
    # so we correctly count line numbers later (ast module bug?)
    source_string = ''
    for line in source:
        if len(line) == 0:
            line = '#\n'
        if line[0] == '@':
            continue
        source_string += line
    return source_string

# Produce the AST for the body of a function
def get_func_ast(func):
    source = get_func_source(func)
    return ast.parse(source).body[0].body

# Get all the ancestors of the current node
def _ancestors(self):
    # Start with the current parent and no ancestors
    parent = self.parent
    ancestors = []

    # Keep going up parents and tracking ancestors until we hit the top
    while parent is not None:
        ancestors.append(parent)
        parent = parent.parent

    return ancestors

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

        # Assign the parent and ancestors method and return the node
        node.parent = parent

        # Keep track of the maximum and minimum line number
        if not node.parent:
            if 'lineno' in node._attributes:
                node.maxlineno = node.lineno
                node.minlineno = node.lineno
            else:
                node.maxlineno = None
                node.minlineno = None
        if node.parent and 'lineno' in node._attributes:
            if hasattr(node.parent, 'maxlineno') and node.parent.maxlineno is not None:
                node.parent.maxlineno = max(node.lineno, node.parent.maxlineno)
            else:
                node.parent.maxlineno = node.lineno

            if hasattr(node.parent, 'minlineno') and node.parent.minlineno is not None:
                node.parent.minlineno = min(node.lineno, node.parent.minlineno)
            else:
                node.parent.minlineno = node.lineno

        node.ancestors = _ancestors.__get__(node, ast.AST)
        return node

# Traverse the AST to identify reads and writes to values
class TaintAnalysis(ast.NodeVisitor):
    def __init__(self, func_or_ast, taint_obj=None):
        # If we were given a function, save it
        if not isinstance(func_or_ast, ast.AST):
            self.func = func_or_ast

            # Get the source code of the function and parse the AST
            source = get_func_source(self.func)
            func_ast = ast.parse(source)
        else:
            func_ast = func_or_ast
            self.func = None

        if taint_obj is not None:
            self.taint_obj = ast.parse(taint_obj).body[0].value
        else:
            self.taint_obj = None
        super(TaintAnalysis, self).__init__()

        # Initialize lists to track usage
        self.read_lines = defaultdict(set)
        self.write_lines = defaultdict(set)
        self.taint_exprs = set()
        self.tainted_by = defaultdict(list)
        self.functions = defaultdict(set)

        # Start visiting the root of the function's AST
        self.func_ast = ParentTransformer().visit(func_ast)
        self.visit(self.func_ast)

    # Get all functions called in this range
    def functions_in_range(self, minlineno=None, maxlineno=None):
        functions = set()
        for function, linenos in self.functions.items():
            for lineno in linenos:
                if (not minlineno or lineno >= minlineno) and \
                   (not maxlineno or lineno <= maxlineno):
                    functions.add(function)
                    break

            if function in functions:
                continue

        return functions

    # Get the identifier to use when recording a read/write
    def get_id(self, node):
        if isinstance(node, ast.Name):
            # Simple variables get recorded by name
            return node.id
        elif isinstance(node, ast.Attribute):
            # We don't track writes to anything not on
            # `self` and assume constants are read-only
            if node.value.id == 'self' or node.attr.isupper():
                return (node.value.id, node.attr)
            else:
                print(ast.dump(node))
                raise Exception()
        elif isinstance(node, ast.Subscript):
            # Record array writes as a write to the whole array
            return self.get_id(node.value)
        elif isinstance(node, (ast.Call, ast.Str)):
            # We only need to track this to propagate
            return node
        else:
            # XXX Debugging for things we don't support
            print(ast.dump(node))
            print(node._fields)
            raise Exception()

    # Check ant propagate taint if necessary
    def check_add_taint(self, source, target):
        if source and source in self.taint_exprs:
            self.tainted_by[target].extend(self.tainted_by[source][:])
            self.taint_exprs.add(target)

    # Initialize the taint information and then visit the node
    def visit(self, node):
        super(TaintAnalysis, self).visit(node)

    # Record a write to a given value
    def visit_Assign(self, node):
        self.visit(node.value)

        for target in node.targets:
            self.write_lines[self.get_id(target)].add(node.lineno)
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
        self.read_lines[var].add(node.lineno)

        self.visit(node.value)

    # Record a read of a simple variable
    def visit_Name(self, node):
        # This ignores parameter names and references to self since
        # we will capture these when we visit Attribute nodes
        if isinstance(node.ctx, ast.Load) and node.id != 'self':
            self.read_lines[node.id].add(node.lineno)

    # Record reads and writes from functions called within our function
    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute):
            # Continue down the tree if we have multiple attribute lookups
            if not isinstance(node.func.value, ast.Name):
                self.visit(node.func)

            # Track this function call
            if isinstance(node.func, ast.Attribute) and \
               isinstance(node.func.value, ast.Name):
                func_id = (node.func.value.id, node.func.attr)
                self.functions[func_id].add(node.lineno)

            # Assume function calls on objects modify data
            self.write_lines[self.get_id(node.func.value)].add(node.lineno)

            # Record this node as one which introduces taint
            if nodes_equal(node.func.value, self.taint_obj):
                self.taint_exprs.add(node)

            # Check for functions on ourself
            # Note that this doesn't currently work when used
            # as a decorator since im_class will not be set
            if isinstance(node.func.value, ast.Name) and \
                    node.func.value.id == 'self' and \
                    hasattr(self.func, 'im_class'):
                other_func = getattr(self.func.im_class, node.func.attr)
                other_args = inspect.getargspec(other_func).args[1:]
                ta = TaintAnalysis(other_func)

                # Copy functions used by the other function
                for func_id in ta.functions.iterkeys():
                    self.functions[func_id].add(node.lineno)

                # Check arguments which were read written
                # Note that we're being pessimistic for writes here since
                # assignments just "write" to the local variable for parameter
                # XXX Doesn't work for functions with starargs or kwargs
                for i, arg in enumerate(node.args):
                    if isinstance(arg, ast.Name):
                        arg_name = other_args[i]
                        if ta.read_lines.has_key(arg_name):
                            self.read_lines[arg.id].add(node.lineno)
                        if ta.write_lines.has_key(arg_name):
                            self.write_lines[arg.id].add(node.lineno)

                # Copy over attribute nodes which were read or written
                for var, _ in ta.read_lines.items():
                    if isinstance(var, tuple):
                        self.read_lines[var].add(node.lineno)

                for var, _ in ta.write_lines.items():
                    if isinstance(var, tuple):
                        self.write_lines[var].add(node.lineno)

        # Visit function parameters to record reads
        for arg in node.args:
            self.visit(arg)
            self.check_add_taint(arg, node)

# Check if two AST nodes are equal
def nodes_equal(node1, node2):
    if node1 is None or node2 is None:
        return False

    # Initialize iterators over both trees
    walk1 = ast.walk(node1)
    walk2 = ast.walk(node2)

    for node1, node2 in itertools.zip_longest(walk1, walk2):
        # Check that there are the same number of fields
        if len(node1._fields) != len(node2._fields):
            return False

        # Check that all field values are equal
        for field1, field2 in itertools.zip_longest(node1._fields, node2._fields):
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

# Produce an AST which contains the necessary lines in the function
def block_including(func_ast, minlineno, maxlineno):
    if isinstance(func_ast, ast.Module):
        func_body = func_ast.body[0].body
    else:
        func_body = func_ast

    body = []
    for node in func_body:
        # If the two ranges overlap, save this node
        minrange = max(node.minlineno, minlineno)
        maxrange = min(node.maxlineno, maxlineno)

        if maxrange >= minrange:
            body.append(node)

    return body

# Get the expressions which are read and written within a given block
def block_inout(func_or_ast, minlineno, maxlineno):
    taint = TaintAnalysis(func_or_ast)
    arg_names = set([getattr(arg, 'id', getattr(arg, 'arg', None)) for arg in taint.func_ast.body[0].args.args])
    
    # Get all functions called in this range
    functions = taint.functions_in_range(minlineno, maxlineno)
    read_lines = taint.read_lines
    write_lines = taint.write_lines
    for function in functions:
        if function[0] == 'self' and hasattr(func_or_ast, 'im_class'):
            # Perform analysis on the other functions
            other_func = getattr(func_or_ast.im_class, function[1])
            other_taint = TaintAnalysis(other_func)

            # Copy over expressions from the helper
            for expr, _ in other_taint.read_lines.items():
                if isinstance(expr, tuple):
                    read_lines[expr].add(minlineno)
            for expr, _ in other_taint.write_lines.items():
                if isinstance(expr, tuple):
                    write_lines[expr].add(minlineno)

    in_exprs = set()
    for obj, lines in taint.read_lines.items():
        # Check if any read happens within our range
        in_range = any(lineno >= minlineno and lineno <= maxlineno
                for lineno in lines)

        # Check if this is a function local variable
        is_local = not isinstance(obj, tuple)

        # Check if there were any previous writes in the function to this value
        written_before = any(lineno < minlineno
                for lineno in taint.write_lines[obj])

        # If in range and not a local used only in this block, include it
        if in_range and (not is_local or written_before or obj in arg_names):
            in_exprs.add(obj)

    out_exprs = set()
    for obj, lines in taint.write_lines.items():
        # Check if any write happens within our range
        in_range = any(lineno >= minlineno and lineno <= maxlineno
                for lineno in lines)

        # Check if this is a function local variable
        is_local = not isinstance(obj, tuple)

        # Check if there are any future reads to this value
        # XXX This doesn't account for the fact that this read may only
        #     occur with an intervening write in which case we don't need this
        reads_after = any(lineno > maxlineno
                for lineno in taint.read_lines[obj])

        # If in range and not a local variable never read again, include it
        if in_range and (not is_local or reads_after):
            out_exprs.add(obj)

    return in_exprs, out_exprs
