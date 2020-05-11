# How to run

In this app:

```jshelllanguage
// step 1
mvn clean install

// step 2
onos-app localhost install target/*.oar
```

After installing in ONOS successfully with app name 'org.onosproject.int.action', go to onos cli:

```jshelllanguage
// show app
> apps -s -a

// activate app
> app activate org.onosproject.int.action

// deactivate app
> app deactivate org.onosproject.int.action
```

If you modify the source code of this file, please re-compile it with above commands.