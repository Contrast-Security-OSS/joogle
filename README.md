joogle
========

Joogle is a static analysis program used primarily to find deserialization attack gadgets.

## Why did you make this?

When building deserialization attacks, you find yourself asking questions like:
* What types have zero argument constructors and a finalize() method?
* What types have non-empty static initializers?
* What types (meet some other condition)?

Joogle gives you a very quick way to answer questions like that. Using an IDE can be helpful for answering some questions like this individually, but never more than one at a time.

## How do I use it?
If you want to use some of our preconfigured search filters, just build Joogle and run the .jar. Here's an example of searching for gadgets just within the JRE that have a zero-argument constructor:

```
$ git pull https://github.com/Contrast-Security-OSS/joogle.git
$ mvn package
$ java -jar target/joogle.jar -zeroArgConstructor

**********
* joogle *
**********
Scanning 1 paths
[!] Matched: sun.nio.cs.ext.Big5 - /jdk8/lib/charsets.jar - http://grepcode.com/search?query=sun.nio.cs.ext.Big5
[!] Matched: sun.nio.cs.ext.Big5_HKSCS - /jdk8/lib/charsets.jar - http://grepcode.com/search?query=sun.nio.cs.ext.Big5_HKSCS
[!] Matched: sun.nio.cs.ext.Big5_HKSCS_2001 - /jdk8/lib/charsets.jar - http://grepcode.com/search?query=sun.nio.cs.ext.Big5_HKSCS_2001
...
[!] Matched: apple.laf.JRSUIUtils - /jdk8/lib/rt.jar - http://grepcode.com/search?query=apple.laf.JRSUIUtils
[!] Matched: apple.laf.JRSUIStateFactory - /jdk8/lib/rt.jar - http://grepcode.com/search?query=apple.laf.JRSUIStateFactory
[!] Matched: apple.laf.JRSUIConstants - /jdk8/lib/rt.jar - http://grepcode.com/search?query=apple.laf.JRSUIConstants
Scanned 19014 classes
Scanned 22 jars
```

The full options are here:
```
usage: joogle
 -allowInner                 allow inner classes to be searched
 -allowInterfaces            allow interfaces to be searched
 -createsType <arg>          find gadgets that create concrete classes of
                             given type
 -csv <arg>                  a target file to dump csv output
 -declaresEqualsOrHashCode   find gadgets that override equals() or
                             hashCode()
 -declaresFinalize           find gadgets that declare finalize() methods
 -i <arg>                    input file containing paths to search,
                             separated by newlines
 -implementsType <arg>       find gadgets that implement (via abstract
                             classes or interfaces)
 -j                          don't include the JRE in the search
 -mode <arg>                 match mode -- values can be AND or OR;
                             default is OR
 -s                          suppress stdout output
 -staticAccessConstructors   find gadgets with zero-arg constructors
                             interacting with static fields/methods
 -v                          include verbose output
 -zeroArgConstructor         find gadgets with zero-arg constructors
```

If you want to create new filters or otherwise control the output, you can import Joogle as a library and call its APIs directly, like this:
```
import com.contrastsecurity.joogle.Joogle;
import com.contrastsecurity.joogle.JoogleContext;
import com.contrastsecurity.joogle.checkers.ZeroArgConstructorChecker

JoogleContext context = new JoogleContext();
context.allowInnerClasses(false);
context.allowInterfaces(false);
context.addChecker(new ZeroArgConstructorChecker()); // filter to classes with zero argument constructors

// add the user JRE to search
Set<Path> paths = new HashSet<Path>();
paths.add(Paths.get(System.getProperty("java.home")));

Joogle joogle = new Joogle();
joogle.scanPaths(paths, context);
```

Happy gadget hunting!

## Limitations
Joogle only statically analyzes code without the runtime  class hierarchy resolved, and therefore may not provide a truly exhaustive list of matching classes. For instance, java.util.HashMap doesn't implement hashCode() directly, but does through inheritance of java.util.AbstractMap. If you ask Joogle to show all classes in the JRE that implement hashCode() and have a zero-argument constructor, HashMap will not show up.
