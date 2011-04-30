from google.appengine.ext import webapp
from google.appengine.ext.webapp import template
import os, logging

class BaseHandler(webapp.RequestHandler):
    def __init__(self):
        self.templates_path = os.path.join(os.path.dirname(__file__), "templates")
    
    def render_template(self, template_path, template_values):
        path = os.path.join(self.templates_path, template_path)
        self.response.out.write(template.render(path, template_values))
    
    def return_template(self, template_path, template_values):
        path = os.path.join(self.templates_path, template_path)
        return template.render(path, template_values)
    
