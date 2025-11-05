from fuzzingbook import GUIFuzzer
from selenium import webdriver
import shutil

BROWSER = 'chrome'
HEADLESS = True

def driver():
    if BROWSER == 'firefox':
        assert shutil.which('geckodriver') is not None, \
            "Please install the 'geckodriver' executable " \
            "from https://github.com/mozilla/geckodriver/releases"
        options = webdriver.FirefoxOptions()
        if HEADLESS:
            # See https://www.browserstack.com/guide/firefox-headless
            options.add_argument("--headless")

        # For firefox, set a higher resolution for our screenshots
        options.set_preference("layout.css.devPixelsPerPx", repr(1.4))
        gui_driver = webdriver.Firefox(options=options)

        # We set the window size such that it fits our order form exactly;
        # this is useful for not wasting too much space when taking screen shots.
        gui_driver.set_window_size(700, 300)

    elif BROWSER == 'chrome':
        assert shutil.which('chromedriver') is not None, \
            "Please install the 'chromedriver' executable " \
            "from https://chromedriver.chromium.org"
        options = webdriver.ChromeOptions()
        if HEADLESS:
            # See https://www.selenium.dev/blog/2023/headless-is-going-away/
            options.add_argument("--headless=new")
        
        gui_driver = webdriver.Chrome(options=options)
        gui_driver.set_window_size(700, 210 if HEADLESS else 340)

    else:
        assert False, "Select 'firefox' or 'chrome' as browser"

    return gui_driver
    

def main():
    print("Hello from psa2025-juice-shop-fuzzer!")

    url = "http://localhost:3000/"
    gui_driver = driver()
    gui_fuzzer = GUIFuzzer.GUICoverageFuzzer(gui_driver)
    gui_runner = GUIFuzzer.GUIRunner(gui_driver)
    
    gui_driver.get(url)
    print(gui_driver.title)
    
    actions = gui_fuzzer.fuzz()
    print(actions)
    result, outcome = gui_runner.run(actions)
    print(outcome)


if __name__ == "__main__":
    main()