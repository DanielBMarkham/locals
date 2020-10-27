open System
open BCrypt.Net
open System.Security.Cryptography

// Thrash -> Churn -> Reproduce -> Codify -> Automate
// Code status: Churn/Reproduce

// DDD
type Tape=string []
type TapeToHexFunction=Tape->string
type HexToTapeFunction=string->Tape
type HashTapeFunction=Tape->string
type DoesTapeMatchHashFunction=Tape->string->bool
type EncryptTapeFunction=Tape->RSA->string
type DecryptTapeFunction=RSA->string->Tape

// helper
let bytesToHex bytes =
    bytes
    |> Array.map (fun (x : byte) -> System.String.Format("{0:X2}", x))
    |> String.concat System.String.Empty
let hexToBytes (s:string) =
  s
  |> Seq.windowed 2
  |> Seq.mapi (fun i j -> (i,j))
  |> Seq.filter (fun (i,j) -> i % 2=0)
  |> Seq.map (fun (_,j) -> Byte.Parse(String j,System.Globalization.NumberStyles.AllowHexSpecifier))
  |> Array.ofSeq

// ProgramData<->Hex String quasi helpers
// Outside In
// File, block, or streams. Pick one
let tapeToHexString:TapeToHexFunction =
  (fun tape->
    let tempFileName=System.IO.Path.GetRandomFileName()
    let fsw=new System.IO.FileStream(tempFileName,IO.FileMode.CreateNew)
    let bf=System.Runtime.Serialization.Formatters.Binary.BinaryFormatter()
    bf.Serialize(fsw,tape) |> ignore
    fsw.Close()
    let serializedBytes= IO.File.ReadAllBytes(tempFileName)
    bytesToHex(serializedBytes)
  )
let hexStringToTape:HexToTapeFunction =
  (fun hex->
    let b=hexToBytes(hex)
    let bf=System.Runtime.Serialization.Formatters.Binary.BinaryFormatter()
    let ms=new System.IO.MemoryStream(b)
    let ret=bf.Deserialize(ms)
    ret :?>Tape
  )

// Tape hashing in and out
let hashTape:HashTapeFunction =
  (fun tape->
    let tapeString=tapeToHexString(tape)
    let ret=BCrypt.EnhancedHashPassword(tapeString)
    ret
  )
let doesTapeMatchHash:DoesTapeMatchHashFunction =
  (fun tape hash->
    let tapeString=tapeToHexString(tape)
    BCrypt.Verify(tapeString, hash);
  )
  
// Encryption in and out
let encryptTape:EncryptTapeFunction =
  (fun tape rsaEng->
    // From MSDN, mostly. CHURN    
    // double translate here, first array to readable hex, then hex to bytes
    let tapeBytes=System.Text.Encoding.UTF8.GetBytes(tapeToHexString(tape))
    let encryptedMsg=rsaEng.Encrypt(tapeBytes, RSAEncryptionPadding.Pkcs1)
    let ret =bytesToHex(encryptedMsg)
    ret
  )
let decryptTape:DecryptTapeFunction =
  (fun rsaEng msg->
    // CHURN    
    let msgBytes=hexToBytes(msg)
    let decryptedMsgBytes=rsaEng.Decrypt(msgBytes, RSAEncryptionPadding.Pkcs1)
    let decryptedHexBytes=bytesToHex(decryptedMsgBytes)
    let decryptedTapeBytes=hexToBytes(decryptedHexBytes)
    let tapeInHex=System.Text.Encoding.UTF8.GetString(decryptedTapeBytes)
    let ret=hexStringToTape(tapeInHex)
    ret
  )

let votingTape =
    [|
        "Dog"
        ;"Cat"
        ;"Cow"
    |]


[<EntryPoint>]
let main argv =


    printfn "\n"
    printfn "ORIGINAL TAPE\n"
    let m3=votingTape 
    printfn "\n %A" m3

    printfn "\n"
    printfn "HEX VERSION OF TAPE\n"
    let m3Hex=tapeToHexString(m3)
    printfn "\n %A" m3Hex

    printfn "\n"
    printfn "DECODED BACK FROM HEX\n"
    let m4=hexStringToTape(m3Hex)
    printfn "\n %A" m4


    let aliceRSA=new System.Security.Cryptography.RSACryptoServiceProvider(4096)
    let alicePublicKey=aliceRSA.ToXmlString(false) // use later

    printfn "\n"
    printfn "RSA ENCODED HEX\n"
    let m5=encryptTape m3 aliceRSA
    printfn "\n %A" m5

    printfn "\n"
    printfn "RSA DECODED HEX\n"
    let m6=decryptTape aliceRSA m5
    printfn "\n %A" m6


    0