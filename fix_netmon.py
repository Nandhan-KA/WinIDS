import sys
import site
from winids.netmon import network_analyzer_tkinter as nat

# Fix missing attribute
old_init = nat.NetworkAnalyzerGUI.__init__
def new_init(self, root):
    old_init(self, root)
    self.overview_animation = None
nat.NetworkAnalyzerGUI.__init__ = new_init

# Fix method signature
old_update_map = nat.NetworkAnalyzerGUI.update_map
def new_update_map(self, frame=None):
    return old_update_map(self)
nat.NetworkAnalyzerGUI.update_map = new_update_map

# Run the app
from winids.netmon.network_analyzer_tkinter import main
main()