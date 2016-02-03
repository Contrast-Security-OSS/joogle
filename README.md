joogle
========

Joogle is an static analysis program used primarily to find deserialization attack gadgets.

## Why did you make this?

When building deserialization attacks, you find yourself asking questions like:
* What types have zero argument constructors and a finalize() method?
* What types have non-empty static initializers?
* What types (meet some other condition)?

This program gives you a very quick way to answer questions like that.

## How do I use it?

The first way is to create a new Joogle object and call it's APIs directly, like this:
```
import com.contrastsecurity.joogle.Joogle;
import com.contrastsecurity.joogle.JoogleContext;

JoogleContext context = new JoogleContext();
context.allowInnerClasses(false);
context.allowInterfaces(false);

// add the user JRE to search
Set<Path> paths = new HashSet<Path>();
paths.add(Paths.get(System.getProperty("java.home")));

		
```
