from fuzzingbook.GUIFuzzer import GUIRunner
from typing import Tuple
import html
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import ElementClickInterceptedException, ElementNotInteractableException, NoSuchElementException, StaleElementReferenceException, NoAlertPresentException, UnexpectedAlertPresentException, TimeoutException
from selenium.webdriver.support import expected_conditions as EC

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

    def do_search(self, input: str):
        try:
            element = self.driver.find_element(By.ID, "mat-input-1")
            element.send_keys(input)
            element.send_keys(Keys.ENTER)
            WebDriverWait(self.driver, self.DELAY_AFTER_FILL)
        except ElementNotInteractableException:
            self.driver.find_element(By.ID, "searchQuery").click()
            self.do_search(input)

    def has_error_xss(self) -> Tuple[str, str]:
        try:
            WebDriverWait(self.driver, timeout=2).until(EC.alert_is_present())
            alert = self.driver.switch_to.alert
            alert.accept()
            WebDriverWait(self.driver, timeout=5, poll_frequency=1).until_not(EC.alert_is_present())
            return "XSS-alert", self.FAIL
        except (TimeoutException, NoAlertPresentException) as e:
            pass

        elems = self.driver.find_elements(By.ID, "xss-soundcloud")
        if (len(elems) > 0): 
            return "XSS-soundcloud", self.FAIL

        return "", self.PASS
    
    def has_error_sqli(self) -> Tuple[str, str] :
        basket_elems = self.driver.find_elements(By.XPATH, "//*[contains(text(),'Your Basket')]")
        if len(basket_elems)>0:
            return "logged in", self.FAIL 

        errors = self.driver.find_elements(By.CLASS_NAME, "error")
    
        if (len(errors) > 0):
            if (errors[0].text != ACCEPTABLE_ERROR_MSG):
                return errors[0].text, self.FAIL         
        
        return "", self.PASS
    
    def oracle(self) -> Tuple[str,str]:
        xss = self.has_error_xss()

        if xss[1] == self.FAIL :
            return xss
        
        sqli = self.has_error_sqli()

        if sqli[1] == self.FAIL :
            return sqli
        
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

        def search(input):
            if self.log:
                print("SEARCH " + input)
            
            self.do_search(input)

        #TODO: fix action instead of this hack
        if "submit('loginButton')" in inp:
            input = inp.split("submit('loginButton')")[0]+"submit('loginButton')"
        elif "javascript:alert" in inp:
            input = "search('<iframe src=\"javascript:alert(\\'xss\\')\">')"
        elif "soundcloud" in inp:
            input = "search('<iframe id=\"xss-soundcloud\" width=\"100%\" height=\"166\" scrolling=\"no\" frameborder=\"no\" allow=\"autoplay\" src=\"https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076&color=%23ff5500&auto_play=true&hide_related=false&show_comments=true&show_user=true&show_reposts=false&show_teaser=true\">')"
        else:
            input = inp

        exec(input, {'__builtins__': {}},
                  {
                      'fill': fill,
                      'check': check,
                      'submit': submit,
                      'click': click,
                      'search': search,
                  })

        return self.oracle() #assert if test has passed or failed