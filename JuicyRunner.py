from fuzzingbook.GUIFuzzer import GUIRunner
from typing import Tuple
import html
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import ElementClickInterceptedException, ElementNotInteractableException, NoSuchElementException, StaleElementReferenceException

ACCEPTABLE_ERROR_MSG = "Invalid email or password."

class JuicyRunner(GUIRunner):
    def __init__(self, driver, log_gui_exploration=False) -> None:
        """Constructor. `driver` is a Selenium Web driver"""
        self.driver = driver
        self.log = log_gui_exploration

    def do_fill(self, name: str, value: str) -> None:
        try:
            element = self.find_element(name)
            element.clear()
            element.send_keys(value)
            WebDriverWait(self.driver, self.DELAY_AFTER_FILL)
        except ElementClickInterceptedException:
            if self.log:
                print("do_fill ElementClickInterceptedException " + self.driver.current_url)
        except ElementNotInteractableException:
            if self.log:
                print("do_fill ElementNotInteractableException " + self.driver.current_url)
        except NoSuchElementException:
            if self.log:
                print("do_fill NoSuchElementException " + self.driver.current_url)
        except StaleElementReferenceException:
            if self.log:
                print("do_fill StaleElementReferenceException " + self.driver.current_url)

    def do_check(self, id: str, state: bool) -> None:
        try:
            element = self.driver.find_element(By.ID, id) #By ID, not name!
            if bool(state) != bool(element.is_selected()):
                element.click()
            WebDriverWait(self.driver, self.DELAY_AFTER_CHECK)
        except ElementClickInterceptedException:
            if self.log:
                print("do_check ElementClickInterceptedException " + self.driver.current_url)
        except ElementNotInteractableException:
            if self.log:
                print("do_check ElementNotInteractableException " + self.driver.current_url)
        except NoSuchElementException:
            if self.log:
                print("do_check NoSuchElementException " + self.driver.current_url)
        except StaleElementReferenceException:
            if self.log:
                print("do_check StaleElementReferenceException " + self.driver.current_url)

    def do_submit(self, id: str) -> None:
        try:
            element = self.driver.find_element(By.ID, id)
            element.click()
            WebDriverWait(self.driver, self.DELAY_AFTER_SUBMIT)
        except ElementClickInterceptedException:
            if self.log:
                print("do_submit ElementClickInterceptedException " + self.driver.current_url)
        except ElementNotInteractableException:
            if self.log:
                print("do_submit ElementNotInteractableException " + self.driver.current_url)
        except NoSuchElementException:
            if self.log:
                print("do_submit NoSuchElementException " + self.driver.current_url)
        except StaleElementReferenceException:
            if self.log:
                print("do_submit StaleElementReferenceException " + self.driver.current_url)

    def do_click(self, name: str) -> None:
        try:
            element = self.find_element(name)
            element.click()
            WebDriverWait(self.driver, self.DELAY_AFTER_CLICK)
        except ElementClickInterceptedException:
            if self.log:
                print("do_click ElementClickInterceptedException " + self.driver.current_url)
        except ElementNotInteractableException:
            if self.log:
                print("do_click ElementNotInteractableException " + self.driver.current_url)
        except NoSuchElementException:
            if self.log:
                print("do_click NoSuchElementException " + self.driver.current_url)
        except StaleElementReferenceException:
            if self.log:
                print("do_click StaleElementReferenceException " + self.driver.current_url)


    def oracle(self) -> Tuple[str,str]:
        errors = self.driver.find_elements(By.CLASS_NAME, "error")
    
        if (len(errors) > 0):
            if (errors[0].text != ACCEPTABLE_ERROR_MSG):
                return errors[0].text, self.FAIL 

        logged_in = not ("login" in self.driver.current_url)
        if logged_in:
            return "logged in", self.FAIL 

        return "", self.PASS

    def run(self, inp: str) -> Tuple[str, str]:
        """Execute the action string `inp` on the current Web site.
        Return a pair (`inp`, `outcome`)."""

        def fill(name, value):
            if self.log:
                print("FILL " + name + " " + value)
            
            self.do_fill(html.unescape(name), html.unescape(value))

        def check(name, state):
            if self.log:
                print("CHECK " + name)

            self.do_check(html.unescape(name), state)

        def submit(name):
            if self.log:
                print("SUBMIT " + name)

            if 'login' in self.driver.current_url:
                self.do_submit(html.unescape(name))        

        def click(name):
            if self.log:
                print("CLICK " + name)
            
            self.do_click(html.unescape(name))

        exec(inp, {'__builtins__': {}},
                  {
                      'fill': fill,
                      'check': check,
                      'submit': submit,
                      'click': click,
                  })

        return self.oracle() #assert if test has passed or failed