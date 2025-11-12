from fuzzingbook.GUIFuzzer import GUIRunner
from typing import Tuple
import html


class JuicyRunner(GUIRunner):
    def run(self, inp: str) -> Tuple[str, str]:
        """Execute the action string `inp` on the current Web site.
        Return a pair (`inp`, `outcome`)."""

        def fill(name, value):
            #print("FILL " + name + " " + value)
            self.do_fill(html.unescape(name), html.unescape(value))

        def check(name, state):
            #print("CHECK " + name)
            self.do_check(html.unescape(name), state)

        def submit(name):
            print("SUBMIT " + name)
            self.do_submit(html.unescape(name))

        def click(name):
            print("CLICK " + name)
            self.do_click(html.unescape(name))

        exec(inp, {'__builtins__': {}},
                  {
                      'fill': fill,
                      'check': check,
                      'submit': submit,
                      'click': click,
                  })
        #TODO: Get more info to conclude if it should pass or not
        return inp, self.PASS