from fuzzingbook.GUIFuzzer import GUIRunner
from typing import Tuple
import html
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait

ACCEPTABLE_ERROR_MSG = "Invalid email or password."

class JuicyRunner(GUIRunner):
    def __init__(self, driver) -> None:
        """Constructor. `driver` is a Selenium Web driver"""
        self.driver = driver
        self.has_error = False

    def do_submit(self, id: str) -> None:
        element = self.driver.find_element(By.ID, id) #By ID, not name!
        element.click()
        WebDriverWait(self.driver, self.DELAY_AFTER_SUBMIT)


    def run(self, inp: str) -> Tuple[str, str]:
        """Execute the action string `inp` on the current Web site.
        Return a pair (`inp`, `outcome`)."""

        def fill(name, value):
            #print("FILL " + name + " " + value)
            if (name != '' and value != ''):
                self.do_fill(html.unescape(name), html.unescape(value))

        def check(name, state):
            #print("CHECK " + name)
            self.do_check(html.unescape(name), state)

        def submit(name):
            #print("SUBMIT ")
            if (name == ''):
                self.do_submit('loginButton') #OBS: Hard-coded id
            else: 
                self.do_submit(html.unescape(name))

            errors = self.driver.find_elements(By.CLASS_NAME, "error")
            print(len(errors))    
    
            if (len(errors) > 0):
                
                if (errors[0].text != ACCEPTABLE_ERROR_MSG):
                    print(errors[0].text)
                    self.has_error = True
                else:
                    print("acceptable error")

        def click(name):
            #print("CLICK " + name)
            self.do_click(html.unescape(name))
        
        exec(inp, {'__builtins__': {}},
                  {
                      'fill': fill,
                      'check': check,
                      'submit': submit,
                      'click': click,
                  })

        if self.has_error:
            return inp, self.FAIL
        
        return inp, self.PASS