val akka26Version = "2.6.4"

name := "gdpr-assist"

version := "0.1"

scalaVersion := "2.13.1"

libraryDependencies ++= Seq(
  "com.typesafe.akka" %% "akka-actor-typed" % akka26Version,
  "com.typesafe.akka" %% "akka-persistence-typed" % akka26Version,
  "com.github.j5ik2o" %% "reactive-aws-kms-core" % "1.2.1",
  "com.typesafe.akka" %% "akka-slf4j" % akka26Version,
  "org.slf4j" % "slf4j-api" % "1.7.30",
  "com.typesafe.akka" %% "akka-testkit" % akka26Version % Test,
  "com.typesafe.akka" %% "akka-actor-testkit-typed" % akka26Version % Test,
  "ch.qos.logback" % "logback-classic" % "1.2.3" % Test,
  "org.scalatest" %% "scalatest" % "3.1.1" % Test
)

scalacOptions ++=
  Seq(
    "-feature",
    "-deprecation",
    "-unchecked",
    "-encoding",
    "UTF-8",
    "-language:_",
    "-target:jvm-1.8"
  )

PB.targets in Compile := Seq(scalapb.gen() -> (sourceManaged in Compile).value)
