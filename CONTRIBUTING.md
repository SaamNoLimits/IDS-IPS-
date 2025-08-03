# Contributing to Enhanced IDS

We love your input! We want to make contributing to Enhanced IDS as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features
- Becoming a maintainer

## Development Process

We use GitHub to host code, to track issues and feature requests, as well as accept pull requests.

## Pull Requests

Pull requests are the best way to propose changes to the codebase. We actively welcome your pull requests:

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation.
4. Ensure the test suite passes.
5. Make sure your code lints.
6. Issue that pull request!

## Any contributions you make will be under the MIT Software License

In short, when you submit code changes, your submissions are understood to be under the same [MIT License](http://choosealicense.com/licenses/mit/) that covers the project. Feel free to contact the maintainers if that's a concern.

## Report bugs using GitHub's [issue tracker](../../issues)

We use GitHub issues to track public bugs. Report a bug by [opening a new issue](../../issues/new); it's that easy!

## Write bug reports with detail, background, and sample code

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code if you can
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you tried that didn't work)

## Development Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/enhanced-ids.git
cd enhanced-ids
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install development dependencies:
```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt  # If available
```

4. Install pre-commit hooks:
```bash
pre-commit install
```

## Code Style

We use several tools to maintain code quality:

- **Black** for code formatting
- **flake8** for linting
- **mypy** for type checking
- **pytest** for testing

Run these before submitting:

```bash
# Format code
black .

# Lint code
flake8 .

# Type check
mypy .

# Run tests
pytest tests/
```

## Testing

- Write tests for any new functionality
- Ensure all tests pass before submitting PR
- Include both unit tests and integration tests where appropriate
- Test with different Python versions if possible

## Documentation

- Update README.md if you change functionality
- Add docstrings to new functions and classes
- Update API documentation if you change interfaces
- Include examples in docstrings where helpful

## Security

- Never commit sensitive information (API keys, passwords, etc.)
- Follow security best practices
- Report security vulnerabilities privately to the maintainers
- Use environment variables for configuration

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## References

This document was adapted from the open-source contribution guidelines for [Facebook's Draft](https://github.com/facebook/draft-js/blob/a9316a723f9e918afde44dea68b5f9f39b7d9b00/CONTRIBUTING.md).
