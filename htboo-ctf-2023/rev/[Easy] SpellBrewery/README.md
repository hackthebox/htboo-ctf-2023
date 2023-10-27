![](https://github.com/hackthebox/writeup-templates/raw/master/challenge/assets/images/banner.png)

<img src="https://github.com/hackthebox/writeup-templates/raw/master/challenge/assets/images/htb.png" style="margin-left: 20px; zoom: 80%;" align=left/>
<font size="10">SpellBrewery</font>
21<sup>st</sup> 09 23 / Document No. D22.102.XX
Prepared By: clubby789
Challenge Author: clubby789
Difficulty: <font color=green>Easy</font>
Classification: Official

# Synopsis

SpellBrewery is an Easy reversing challenge. Players will decompile a .NET application to recover the logic of a flag checker.

## Skills Required
    - Basic scripting
## Skills Learned
    - Use of a .NET decompiler

# Solution

Inside the download, there are 4 files.
- `SpellBrewery`, a large ELF
- `SpellBrewery.deps.json`, listing some `.NET` dependencies
- `SpellBrewery.dll`, a console `.NET` assembly (listed by the `file` command)
- `SpellBrewery.runtimeconfig.json`, identifying it as a .netCORE 7.0 app

We can clearly identify this DLL as a .NET program, with the .NET runtime likely being bundled in the ELF.

## Decompiling

.NET is very easy to decompile, and many tools exist to decompile it almost to source code.
Many solutions are available depending on platform and preference, such as DnSpy, ILSpy, ILSpy for VSCode, DotPeek. We'll open it in our tool of choice.

Initially, we can see a `SpellBrewery` namespace, containing 3 classes: `Menu`, `Ingredient`, `Brewery`.

## `Menu`

The `Menu` class defines an enum,
```csharp
public enum Choice
{
    ListIngredients,
    DisplayRecipe,
    AddIngredient,
    BrewSpell,
    ClearRecipe
}
```
and a static method `RunMenu` which returns a `Choice`.

```csharp

public static Choice RunMenu()
{
    Console.WriteLine("1. List Ingredients");
    Console.WriteLine("2. Display Current Recipe");
    Console.WriteLine("3. Add Ingredient");
    Console.WriteLine("4. Brew Spell");
    Console.WriteLine("5. Clear Recipe");
    Console.WriteLine("6. Quit");
    Console.Write("> ");
    // .. SNIP ..
}
```

## `Ingredient`

`Ingredient` simply wraps a single `string` property called `name`. It ovverides the `ToString`, `Equals` and `GetHashCode` methods, all of which forward to the `name` property.

## `Brewery`

This contains the bulk of the program. We define 3 static properties:

```csharp
	private static readonly string[] IngredientNames = new string[106]
	{
		/* List Of Ingredient Names */
	};

	private static readonly string[] correct = new string[36]
	{
		/* Shorter list of ingredient names */
	};

	private static readonly List<Ingredient> recipe = new List<Ingredient>();
```

The `Main` function simply calls `RunMenu` and calls a function based on the result.

### `ListIngredients`

```csharp
for (int i = 0; i < IngredientNames.Length; i++) {
    Console.Write(IngredientNames[i] ?? "");
    if (i + 1 < IngredientNames.Length) {
        Console.Write(", ");
    }
    if (i % 6 == 5) {
        Console.Write("\n");
    }
}
Console.Write("\n");
```

This simply prints all ingredient names in `IngredientNames`.

### `DisplayRecipe`

```csharp
private static void DisplayRecipe()
{
    if (recipe.Count == 0) {
        Console.WriteLine("There are no current ingredients");
    } else {
        Console.WriteLine(string.Join(", ", recipe));
    }
}
```

This prints out the current ingredients in `recipe`.

### `AddIngredient`

```csharp
private static void AddIngredient() {
    Console.Write("What ingredient would you like to add? ");
    string text;
    while (true) {
        text = Console.ReadLine();
        if (IngredientNames.Contains(text)) {
            break;
        }
        Console.WriteLine("Invalid ingredient name");
    }
    recipe.Add(new Ingredient(text));
    string value = ("aeiou".Contains(char.ToLower(text[0])) ? "an" : "a");
    Console.WriteLine($"The cauldron fizzes as you toss in {value} '{text}'...");
}
```

This takes an ingredient name from the user and, if valid, adds a new `Ingredient` with that name to the recipe. It prints out a message with the correct article for the name based on whether it begins with a vowel.

### `ClearRecipe`

```csharp
private static void ClearRecipe() {
    recipe.Clear();
    Console.WriteLine("You pour the cauldron down the drain. A fizzing noise and foul smell rises from it...");
}
```

This resets the recipe list.

### `BrewSpell`

```csharp
private static void BrewSpell() {
    if (recipe.Count < 1) {
        Console.WriteLine("You can't brew with an empty cauldron");
        return;
    }
    byte[] bytes = recipe.Select((Ingredient ing) => (byte)(Array.IndexOf(IngredientNames, ing.ToString()) + 32)).ToArray();
    if (recipe.SequenceEqual(correct.Select((string name) => new Ingredient(name)))) {
        Console.WriteLine("The spell is complete - your flag is: " + Encoding.ASCII.GetString(bytes));
        Environment.Exit(0);
    } else {
        Console.WriteLine("The cauldron bubbles as your ingredients melt away. Try another recipe.");
    }
}
```

This uses Linq to transform our recipe. For each ingredient, we find its index in `IngredientNames`, and add 32. We then compare the recipe to `correct` (after converting each string to an `Ingredient`). If they match, `bytes` is converted to a string and printed as the flag. Otherwise, it's incorrect.

## Solving

We can now see that each ingredient represents an ASCII character, starting at 32 (space). We can solve this in one of two ways - statically, by creating the flag from the `correct` list, or entering each `correct` name and printing the result. We'll implement the first.

We'll begin by defining our `ingredients` and `correct`.

```py
ingredients = [/* snip */]
flag_data = [/* snip */]
```

We can then take the index of each, add 32/0x20 and convert it to a string.

```py
print("".join(chr(ingredients.index(f) + 0x20) for f in flag_data))
```