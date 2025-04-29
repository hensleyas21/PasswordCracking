import java.security.MessageDigest
import java.util.concurrent.{ExecutorService, Executors}
import scala.collection.parallel.CollectionConverters.*
import scala.collection.{AbstractIterable, AbstractIterator, mutable}
import scala.concurrent.duration.*
import scala.concurrent.{Await, ExecutionContext, Future}
import scala.concurrent._
import ExecutionContext.Implicits.global
import scala.util.{Failure, Success}

// Instructor Example Times
// Sequential: Found 83 passwords of length 4 in 921.411 seconds
// Parallel:   Found 83 passwords of length 4 in 151.388 seconds (8-core CPU)

@main def crackPasswords(): Unit = {
  // load password hashes from the starter pack
  val hashes: Set[String] = getHashes
  // define some character sets to test against the hashes
  val digits = "0123456789"
  val lowercase = "abcdefghijklmnopqrstuvwxyz"
  val uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  val symbols = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
  val fullCharset = lowercase + uppercase + digits + symbols
  // try brute forcing all passwords of a specific length n
  val length = 3
  val (duration, passwords) = timeIt(bruteForceLoop(fullCharset, length, hashes))
  val (time, p) = timeIt(Await.ready(parallelBruteForce(fullCharset, length, hashes), 10.seconds).value match
    case None => Set.empty[String]
    case Some(response) => response match
      case Failure(exception) => throw exception
      case Success(result) => result
  )
  val (time2, p2) = timeIt(Await.ready(allDigits(6, hashes), 10.seconds).value match
    case None => Set.empty[String]
    case Some(response) => response match
      case Failure(exception) => throw exception
      case Success(result) => result
  )
  val (time3, p3) = timeIt(repeatedCharacters(fullCharset, 26, hashes))
  val (time4, p4) = timeIt(mostCommonPasswords(hashes))

  println(s"Time ran: ${time} ms")
  println(s"One Character Passwords: ${p.mkString(", ")}")

  println(s"Time ran: ${time2} ms")
  println(s"All-digit Passwords: ${p2.mkString(", ")}")

  println(s"Time ran: ${time3} ms")
  println(s"Repeated-character Passwords: ${p3.mkString(", ")}")

  println(s"Time ran: ${time4} ms")
  println(s"Most Common Passwords: ${p4.mkString(", ")}")

  println(s"Time ran: ${duration} ms")
  println(s"One Character Passwords: ${passwords.mkString(", ")}")
  // note that the getCombination function could also be used to combine words . . .
  val words = Vector("correct", "horse", "battery", "staple")
  println(getCombination(words)(2)(BigInt(7)).mkString)
}

// brute force try every order of chars in charset with replacement using collection methods
def bruteForceCollection(charset: String, length: Int, hashes: Set[String]): Iterable[String] = {
  // identify the range of BigInt that correspond to possible passwords
  val start = BigInt(0)
  val stop = BigInt(charset.length).pow(length)
  // partially apply getCombination to get a simpler function
  val makeCombination = getCombination(charset)(length)
  // use collection methods on a range of BigInts to find possible passwords and filter for ones with matching hashes
  (start until stop).view
    .map((x: BigInt) => makeCombination(x).mkString)
    .filter((pwd: String) => hashes contains sha256(pwd))
}

// brute force try every order of chars in charset with replacement using a for loop
// NOTE: this one might be an easier starting point for futures and doesn't have issues with Int.MaxValue
def bruteForceLoop(charset: String, length: Int, hashes: Set[String]): Iterable[String] = {
  val start = BigInt(0)
  val stop = BigInt(charset.length).pow(length)
  // create a partially applied version of get combination with symbols and length filled in
  val makeCombination = getCombination(charset)(length)
  // create a buffer to hold passwords that have been identified
  val passwords = mutable.ArrayBuffer[String]()
  // loop from the first possible password with this charset to the last checking each
  var cursor = start
  while cursor < stop do {
    // identify the password that goes with this particular number
    val password = makeCombination(cursor).mkString
    // if this password's hash is in the set, add the password to the output list of passwords
    if hashes contains sha256(password) then passwords.addOne(password)
    // increment the cursor
    cursor += 1
  }
  // convert the buffer to an immutable vector and return it
  passwords.toVector
}

// compute the SHA-256 hash of the string using Java's message digest tools
def sha256(text: String): String = {
  MessageDigest.getInstance("SHA-256")
    .digest(text.getBytes("UTF-8"))
    .map("%02x".format(_)).mkString.toUpperCase
}

/**
 * Converts a BigInt into a number in base symbols.size where symbols are the digits.
 * These conversions are restricted by length (number of digits) and include the
 * equivalent of leading zeros to better match the application.
 *
 * @param symbols - the symbols in this base (IndexedSeq for efficient index lookup)
 * @param length -  the number of 'digits' in the output symbol sequence
 * @param index - the number to be converted into a set of symbols in base symbols.size
 * @tparam A    - the type of the symbols (often but not necessarily characters)
 * @return      - a sequence of length possibly repeating items from the symbols unique by index
 */
def getCombination[A](symbols: IndexedSeq[A])(length: Int)(index: BigInt): Seq[A] = {
  // check that the input is in range
  if index < BigInt(0) || index >= BigInt(symbols.size).pow(length) then {
    throw new IndexOutOfBoundsException("Symbol sequence index out of range")
  }
  // create a number buffer to track what symbol comes next
  var numBuffer: BigInt = new BigInt(index.bigInteger)
  // create an output array of items of type A
  val out = mutable.ArrayBuffer[A]()
  // fill the output based on the values of the buffer
  for i <- 0 until length do {
    // interpret the lowest portion of the number as the next symbol
    val next = symbols(numBuffer.mod(symbols.size).toInt)
    out.addOne(next)
    // remove that portion with integer division
    numBuffer /= symbols.size
  }
  // return the updated output buffer as a vector
  out.toVector
}

/**
 * Returns both the answer and the clock time required to compute it for any expression
 *
 * @param f the expression to be executed
 * @tparam A the type to which f evaluates
 * @return the time to compute and value of f
 */
def timeIt[A](f: => A): (Double, A) = {
  val startTime = System.currentTimeMillis()
  val result = f
  val endTime = System.currentTimeMillis()
  (endTime-startTime, result)
}

// loads a set of password hashes from the provided hashes.txt file
def getHashes: Set[String] = {
  val src = io.Source.fromInputStream(
    getClass.getClassLoader.getResourceAsStream("hashes.txt"))
  try {
    src.getLines().toSet
  } finally {
    src.close()
  }
}


def parallelBruteForce(chars: String, length: Int, hashes: Set[String]): Future[Iterable[String]] ={
  //get the number of cores to determine the number of threads we need
  val numThreads = Runtime.getRuntime.availableProcessors()

  //start at password 0
  val start = BigInt(0)
  //go to the total number of possible passwords
  val stop = BigInt(chars.length).pow(length)

  //divide how many passwords each thread should be checking, the plus one is to catch passwords missed when rounding
  val pwdsPerThread = (stop / numThreads) + 1

  //make same call as non parallelized function
  val makeCombination = getCombination(chars)(length)

  //make a future for each thread and its results
  val futures = (0 until numThreads).map { i =>
    Future {
      //get which password to start with based on what thread is running
      val threadStart = start + (i * pwdsPerThread)
      val threadEnd = (threadStart + pwdsPerThread).min(stop)
      val passwords = mutable.ArrayBuffer[String]()
      var cursor = threadStart

      //same password checking like in brute force above
      while (cursor < threadEnd) {
        val pwd = makeCombination(cursor).mkString
        if hashes contains sha256(pwd) then passwords.addOne(pwd)
        cursor += 1
      }
      passwords
    }
  }
  //make this into one Future sequence and flattened into one list of passwords
  Future.sequence(futures).map(_.flatten)
}

def allDigits(numDigits: Int, hashes: Set[String]): Future[Iterable[String]] = numDigits match {
  case 0 => Future(List())
  case _ => Future.reduceLeft(List(parallelBruteForce("1234567890", numDigits, hashes), allDigits(numDigits-1, hashes)))(_ ++ _)
}

def repeatedCharacters(chars: String, length: Int, hashes: Set[String]): Iterable[String] = length match {
  case 0 => List()
  case _ => chars.view.map(c => c.toString * length).filter(pwd => hashes.contains(sha256(pwd))) ++ repeatedCharacters(chars, length-1, hashes)
}

def mostCommonPasswords(hashes: Set[String]): Iterable[String] = {
  val src = io.Source.fromInputStream(
    getClass.getClassLoader.getResourceAsStream("most_common_pwds.txt"))
  try {
    src.getLines().filter(pwd => hashes.contains(sha256(pwd))).toList
  } finally {
    src.close()
  }
}