# KANAPL

KANAPL is an APL interpreter written by JavaScript.

## How to use

Write the script tag in your Web site.

```html
<script src="kanapl.js"></script>
```

To create APL environment, call KANAPL function.

```javascript
var aplenv = KANAPL();
```

APL environment has two methods.

### aplenv.eval()

Evaluate the given APL program and return evaluated array or scalar.

```javascript
var result = aplenv.eval("3÷2 2ρ1 2 3 4");
```

### aplenv.put()

Bind the given array or scalar.  
The array is validated and throws an error if the array is not valid.

```javascript
aplenv.put("A", [1, 2, 3, 4]);
```

## Variable name

The characters shown as follows are vaild for variable name.

* Uppercase ASCII alphabets
* Kanji (Hanzi)
* Hiragana
* Katakana
* △
* Full width alphabets (Uppercase and Lowercase)
* Half width Katakana

## APL characters

KANAPL can use below APL features.  
KANAPL also can use ASCII sequence surrounded by #.

|Feature|APL|KANAPL|Sequence|
|:--|:--|:--|:--|
|Negative sign|￣|￣|#~#|
|Addition|+|+||
|Subtraction|-|-||
|Multiplication|×|×|#&#x002A;#|
|Division|÷|÷|#/#|
|Modulo/Absolute|&#x007C;|&#x007C;||
|Maximum/ceiling|&#x2308;|「|#max#|
|Minimum/floor|&#x230A;|」|#min|
|Power/Exponent|★|★|#&#x002A;&#x002A;#|
|Logarithm|&#x235F;|☆|#log#|
|Random|?|?||
|Pi/Trigonometric Function|〇|〇|#tri#|
|Factorial/Combination|!|!||
|Logical Not|～|～|#not#|
|Logical And|∧|∧|#and#|
|Logical Or|∨|∨|#or#|
|Logical Nand|&#x2372;|†|#nand#|
|Logical Nor|&#x2371;|‡|#nor#|
|Reduce|/|/||
|Scan/Expand|\\|\\||
|Inner product|.|.||
|Outer product|&#x2218;.|・.|#outer#|
|Shape/Reshape|ρ|ρ|#rho#|
|Concatenate|,|,||
|Take|↑|↑|#take#|
|Drop|↓|↓|#drop#|
|Reverse/Rotate|&#x233D;|φ(Phi)|#rotate#|
|Transpose|&#x2349;|〆|#transpose#|
|Index generator|ι|ι|#iota#|
|Member of|∈|∈ ε|#in#|
|Sort(ascending)|&#x234B;|♯(Sharp)|#asc#|
|Sort(descending)|&#x2352;|♭|#desc#|
|Inverse Matrix/Division Matrix|&#x2339;|※|#domino#|
|Encode|⊥|⊥|#encode#|
|Decode|&#x22A4;|┬|#decode#|
|Execute|&#x234E;|♪|#eval#|
|Format|&#x2355;|◆|#tostring#|
|Assign|←|←|#<-#|

## Limitation

* User defined function and jump is not avaiable.
* All elements of array must be numbers or characters. (Mixed array is not available)
* All length of array in another array must be the same.

