from fuzzingbook.GUIFuzzer import fsm_diagram
from selenium import webdriver
from selenium.common.exceptions import ElementClickInterceptedException, ElementNotInteractableException, NoSuchElementException

from JuicyGrammarMiner import JuicyGrammarMiner
from JuicyRunner import JuicyRunner
from JuicyFuzzer import JuicyFuzzer

import shutil

BROWSER = 'chrome'
HEADLESS = False
ITERATIONS = 5

def driver():
    if BROWSER == 'firefox':
        assert shutil.which('geckodriver') is not None, \
            "Please install the 'geckodriver' executable " \
            "from https://github.com/mozilla/geckodriver/releases"
        options = webdriver.FirefoxOptions()
        if HEADLESS:
            options.add_argument("--headless")

        # For firefox, set a higher resolution for our screenshots
        options.set_preference("layout.css.devPixelsPerPx", repr(1.4))
        gui_driver = webdriver.Firefox(options=options)

        gui_driver.set_window_size(1400, 800)

    elif BROWSER == 'chrome':
        assert shutil.which('chromedriver') is not None, \
            "Please install the 'chromedriver' executable " \
            "from https://chromedriver.chromium.org"
        options = webdriver.ChromeOptions()
        if HEADLESS:
            options.add_argument("--headless=new")
        else:
            options.add_experimental_option("detach", True) 

        gui_driver = webdriver.Chrome(options=options)
        gui_driver.set_window_size(1400, 800)
        gui_driver.implicitly_wait(2)

    else:
        assert False, "Select 'firefox' or 'chrome' as browser"

    return gui_driver
    

def main():
    print("Hello from psa2025-juice-shop-fuzzer!")

    url = "http://localhost:3000/#/login"
    gui_driver = driver()
    gui_driver.get(url)

    gui_miner = JuicyGrammarMiner(gui_driver)
    gui_fuzzer = JuicyFuzzer(gui_driver, miner=gui_miner, log_gui_exploration=False)
    gui_runner = JuicyRunner(gui_driver)

    gui_fuzzer.explore_all(gui_runner)

    for _ in range(ITERATIONS):
        try:
            symbol, outcome = gui_fuzzer.run(gui_runner)
            print(outcome)
        except ElementClickInterceptedException as e:
            print("ElementClickInterceptedException")
            pass
        except ElementNotInteractableException as e:
            print("ElementNotInteractableException")
            pass
        except NoSuchElementException as e:
            print("NoSuchElementException")
            pass

    #print(fsm_diagram(gui_fuzzer.grammar))


if __name__ == "__main__":
    main()