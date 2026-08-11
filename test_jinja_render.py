from jinja2 import Environment, FileSystemLoader
from argus.workspace.models import Conversation
env = Environment(loader=FileSystemLoader('/home/varun/argus/argus/workspace/web/templates'))
template = env.get_template('workspace.html')
conv = Conversation(title="Test", conversation_id="123")
try:
    print(template.render(conversation=conv))
except Exception as e:
    import traceback
    traceback.print_exc()
