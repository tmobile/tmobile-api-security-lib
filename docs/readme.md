# Building Docs Using Sphinx

## Install Required Packages

Install following packages using Python package manager.

```bash
pip install sphinx 
pip install mr2
pip install sphinx_rtd_theme
```

## Building HTML Docs

Build the HTML docs by running the following command from `tmobile-api-security-lib/docs` directory.

```bash
cd tmobile-api-security-lib/docs
make html
```

The above command will take care of building HTML docs inside `tmobile-api-security-lib/docs/build` directory.

## Pushing HTML Docs

Once the docs are build, it can be pushed to the `tmobile-api-security-lib` GitHub repository.

Once the docs are pushed to GitHub repo, it will be served by gh-pages via URL https://tmobile.github.io/tmobile-api-security-lib.


