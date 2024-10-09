<p align="center">
  <img src="https://github.com/looplex-osi/server/blob/master/logomark.png?raw=true" alt="@looplex/server logomark" width="512" />
</p>

[![Parcel](https://img.shields.io/badge/built_by-parcel-8DD6F9.svg?style=for-the-badge&logo=webpack)](https://parceljs.org/getting-started/library/)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-f7df1e.svg?style=for-the-badge&logo=standardjs)](https://standardjs.com)
[![Node.js Test Runner](https://img.shields.io/badge/test_by-node-c21325.svg?style=for-the-badge&logo=nodedotjs)](https://nodejs.org/api/test.html)
[![Software Composition Analysis](https://img.shields.io/badge/sca_by-dependabot-025E8C.svg?style=for-the-badge&logo=dependabot)](https://github.com/features/security)
[![Static Application Security Test](https://img.shields.io/badge/sast_by-codeql-0f305f.svg?style=for-the-badge&logo=snyk)](https://codeql.github.com/)
[![Commitizen Friendly](https://img.shields.io/badge/commitizen-friendly-f05032.svg?style=for-the-badge&logo=git)](http://commitizen.github.io/cz-cli/)
[![Semantic Release](https://img.shields.io/badge/semantic-release-cb3837.svg?style=for-the-badge&logo=semantic-release)](https://semantic-release.gitbook.io/semantic-release/)
[![Code Coverage](https://img.shields.io/badge/observability_with-coverage-3F5767.svg?style=for-the-badge&logo=coveralls)](https://coveralls.io/)

# About

`@looplex/server` plays an important role in our platform engineering mission. It's useful at server environments.

# Features

- [Modern Build Tool](https://parceljs.org/getting-started/library/)
- [Native Assertion Module](https://nodejs.org/api/assert.html)
- [Native Test Runner](https://nodejs.org/api/test.html)
- [Native Watch Mode](https://nodejs.org/docs/v20.12.1/api/test.html#watch-mode)
- [Built-in Software Composition Analysis (SCA)](https://github.com/dependabot)
- [Built-in Static Application Security Testing (SAST)](https://codeql.github.com/)
- [Enforced Coding Standard](https://standardjs.com/)
- [Enforced Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
- [Enforced Semantic Release](https://semver.org/)

# Usage

`@looplex/server` is available and ready for use on all Looplex server enviornment. But if, for some reason, you want to leverage it as a standalone, the easiest way to install is by running:

```bash
npm install @looplex/server
```

# Standards and Rules

| Context                                |                            Specification                             |
|:---------------------------------------|:--------------------------------------------------------------------:|
| Storing and Sharing **Date and Time**  | [ISO 8601 Z](https://www.iso.org/iso-8601-date-and-time-format.html) |
| Storing and Sharing **Country Codes**  |     [ISO 3166](https://www.iso.org/iso-3166-country-codes.html)      |
| Storing and Sharing **Language Codes** |     [ISO 639-1](https://www.iso.org/iso-639-language-codes.html)     |
| Storing and Sharing **Currency Codes** |     [ISO 4217](https://www.iso.org/iso-4217-currency-codes.html)     |
| Runtime **Charset**                    |                            UTF-8 (65001)                             |
| Runtime **Language Code**              |                             en-US (1033)                             |

# Contributing

We welcome contributions! Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo, make changes and create a pull request. You can also simply open an issue with the tag "enhancement". Don't forget to give the project a star! Thanks again!

This GitHub repository adheres to the principles of [GitHub Flow](https://docs.github.com/en/get-started/using-github/github-flow) as outlined in the official GitHub documentation. We ensure that all changes are made through branch-based workflows, enabling collaborative development and efficient code review before integration into the main branch.

```mermaid
gitGraph
    commit id:"fix(api): export endpoint should be consistent with output clause"
    branch feature/amazing
    checkout feature/amazing
    commit id:"feat(amazing): implement mvp"
    checkout main
    merge feature/amazing
    branch hotfix/cicd
    checkout hotfix/cicd
    commit id:"fix(cicd): automatic deployment"
    checkout main
    merge hotfix/cicd
    branch feature/incredible
    checkout feature/incredible
    commit id:"feat(incredible): implement mvp"
    checkout main
    merge feature/incredible
```

1. Fork the Project
1. Create your Feature Branch (`git checkout -b feature/amazing`)
1. Commit your Changes (`npm run commit`)
1. Push to the Branch (`git push origin feature/amazing`)
1. Open a Pull Request

# Maintainers

As soon as the maintainers are satisfied with the feature set to be released, they should:

1. Evaluate the quality of the package through the bundle-analyzer report.
1. Run `npm run release`.
1. Confirm if the package is available in npm as the latest version.
1. Notify the maintainers of project embedding this library for faster adoption.

# License

This project is licensed under the Looplex Limited Public License. Feel free to edit and distribute this template as you like.

See [`LICENSE.md`](/LICENSE.md) for more information.

# Acknowledgments
* Special thanks to CEO Angelo Caldeira for enabling this initiative and to our CTO [Fabio Nagao](https://github.com/nagaozen/) who created the framework of this library.
* Shoutout to [looplex contributors](https://github.com/orgs/looplex/people) for their outstanding effort on releasing open source software.

# Useful links
* [README logos](https://stock.adobe.com/br/contributor/208853516/hasan?load_type=author) -- logos repository with the same pattern we are using.
* [Simple Icons](https://simpleicons.org/) -- `shields.io` badges icons and colors.
* [JSDoc Reference](https://www.typescriptlang.org/docs/handbook/jsdoc-supported-types.html) for great DX without enforcing a transpilation.
* [OWASP Application Security Tools](https://owasp.org/www-community/Free_for_Open_Source_Application_Security_Tools)