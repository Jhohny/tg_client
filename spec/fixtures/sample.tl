// Test fixture covering the TL features tg_client cares about.

boolFalse#bc799737 = Bool;
boolTrue#997275b5 = Bool;

simple#11111111 a:int b:long c:string = Simple;

inputPeerUser#7b8e7de6 user_id:long access_hash:long = InputPeer;
inputPeerChat#35a95cb9 chat_id:long = InputPeer;

withFlags#22222222 flags:# name:string maybe:flags.0?string toggle:flags.1?true count:flags.2?int = WithFlags;

withVector#33333333 ids:Vector<long> = WithVector;

wrapper#44444444 peer:InputPeer note:string = Wrapper;

// Bare type pair (for %Bare references in MTProto inner messages)
bareMsg msg_id:long body:Object = BareMsg;
bareContainer#55555555 items:vector<%BareMsg> = BareContainer;

---functions---

doSignIn#66666666 phone:string code:int = Bool;
doSendMessage#77777777 peer:InputPeer text:string = Wrapper;
