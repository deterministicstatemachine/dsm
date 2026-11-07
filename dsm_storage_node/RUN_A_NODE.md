# Run a DSM storage node

You're running one of the five public nodes that hold DSM's data. You don't need to know how any of it works. It takes about 15 minutes, and you only paste one line.

You'll need:

- A Google account
- A credit or debit card (Google asks for one when you sign up)
- The **one line** the DSM team sent you. It already has your seat number in it, and nobody else has the same one.

## What it costs

Google's free trial gives new accounts **$300 of credit for 90 days**, which is more than this node uses. During the trial, Google won't charge your card.

**After 90 days, you pay for your node.** Budget roughly **$30–35 a month**. That's our estimate from Google's prices in November 2026: about $24 for the machine and $5 for the disk, plus the address and internet traffic. Your bill can differ.

> **Upgrade before day 80.** If your trial ends without an upgrade, Google shuts your node down. You then have 30 days to upgrade and get it back. After that, your node's data may be gone for good, and your seat can't be recovered.
>
> To upgrade, open the [Google Cloud console](https://console.cloud.google.com) and click **Activate** or **Upgrade** at the top of the page. Put a reminder in your calendar now.

## Step 1: Sign up for Google Cloud

1. Go to [cloud.google.com/free](https://cloud.google.com/free) and click **Get started for free**.
2. Sign in with your Google account, accept the terms, and enter your card details.
3. Wait until you see the Google Cloud console page. Google has now made your first project for you.

Already used a Google Cloud free trial on this account? You won't get the credit again, so the node is charged to your card from day one.

## Step 2: Open Cloud Shell

Go to [shell.cloud.google.com](https://shell.cloud.google.com). A black terminal window opens in your browser. This is Google's own tool, and nothing gets installed on your computer.

## Step 3: Paste your line

1. Click in the black window and paste the line the DSM team sent you. It looks like this, ending in your seat number:

   ```
   curl -fsSL https://raw.githubusercontent.com/deterministicstatemachine/dsm/main/dsm_storage_node/deploy/operator/launch_on_google_cloud.sh | bash -s -- start 3
   ```

2. Press **Enter**.
3. If Google asks you to **Authorize Cloud Shell**, click **Authorize**.
4. Wait about five minutes and keep the page open. You'll see it work through steps 1 to 5.

## Step 4: Send back your code

When it's done, you'll see this:

```
----- YOUR NODE'S CODE: copy everything between the lines -----
DSMNODE1:H4sIAAAAAAAA...
---------------------------------------------------------------
```

Copy the whole long line that starts with `DSMNODE1:` and send it to the person who invited you. It's safe to send by email or chat because it holds no passwords or keys.

**That's it.** Once all five nodes are running, your node finishes joining by itself.

## Afterwards

Leave your node running. It doesn't need you day to day. Everything below goes in Cloud Shell, the same black window as before.

**Check on your node:**

```bash
curl -fsSL https://raw.githubusercontent.com/deterministicstatemachine/dsm/main/dsm_storage_node/deploy/operator/launch_on_google_cloud.sh | bash -s -- status
```

**Update it**, only when the DSM team asks you to:

```bash
curl -fsSL https://raw.githubusercontent.com/deterministicstatemachine/dsm/main/dsm_storage_node/deploy/operator/launch_on_google_cloud.sh | bash -s -- update
```

**See your code again:**

```bash
curl -fsSL https://raw.githubusercontent.com/deterministicstatemachine/dsm/main/dsm_storage_node/deploy/operator/launch_on_google_cloud.sh | bash -s -- code
```

## Please don't

- **Don't delete the machine, its disk or its project.** The disk holds your node's memory, and a node that loses it can never rejoin as the same seat. Google blocks accidental deletion of the machine, but it can't protect you from deleting the whole project.
- **Don't restore the disk from an old backup or snapshot.** A node that goes back in time could break promises it already made, which is worse than losing it. If something goes wrong with the disk, tell the DSM team.
- **Don't let your payment lapse.** Google shuts down the node if your account stops being paid.
- **Don't change the machine's address or firewall settings.** Phones and the other nodes find your node at its address.

## Your node, your responsibility

The account is yours, and so are the machine and the bills. The security key for your node was made on your machine and stays there. Nobody at DSM can see it or log in to your node, including the person who invited you.

Your node can't open people's sealed messages, and it can't approve or refuse anyone's payments. It stores what it's given and hands it back.

## If something goes wrong

**It stopped halfway, or your browser closed.** Paste the same line again. It picks up where it left off and never replaces what's already there.

**"That did not work: ... no billing account".** Your Google Cloud sign-up isn't finished. Go back to step 1, then paste the line again.

**"That did not work: could not download..."** Tell the person who invited you. Something needs fixing on our side, not yours.

**Anything else.** Send the person who invited you a screenshot of the black window. It holds nothing secret.
