# liboqs-node

Node.js bindings for [liboqs](https://github.com/open-quantum-safe/liboqs) (Open Quantum Safe) through [liboqs-cpp](https://github.com/open-quantum-safe/liboqs-cpp).

```js
const {
  Random, // Utilities for generating secure random numbers
  KEMS, // Information on supported key encapsulation mechanisms
  KeyEncapsulation, // Key encapsulation class and methods
  Sigs, // Information on supported signature algorithms
  Signature // Signature class and methods
} = require("liboqs-node");
```

## Installing

1. Install dependencies:

On Ubuntu:
```bash
  sudo apt install astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind
```

2. Clone the Repository
```bash
git clone https://github.com/sneh2102/liboqs-node-wrapper.git
```

3. Run the commands
```bash
npm i
npm run prep
npm run build:all
```

4. Execute the example code
```bash
node example_kems.js
```