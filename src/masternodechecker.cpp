#include "darksend.h"
#include "masternodechecker.h"
#include "masternode.h"

void CMasternodeChecker::AddMasternode(CMasterNode* mn, bool fVerified)
{
    if(AlreadyHave(mn))
        return;

    printf("***CMasternodeChecker::AddMasternode adding mn\n");

    if(fVerified)
    {
        mapAccepted[mn->vin.prevout.ToString()] = *mn;

        //this is redundant, ultimately it would be best to refactor legacy code
        vecMasternodes.push_back(*mn);
        return;
    }
    else
        mapPending[mn->vin.prevout.ToString()] = *mn;

    BOOST_FOREACH(CNode* pnode, vNodes)
    {
        //check if we have this peer already
        if(pnode->addr == mn->addr)
            return;
    }

    //we dont have this peer so mark as a temporary connection
    mapTemp[mn->vin.prevout.ToString()] = *mn;
}

void CMasternodeChecker::Accept(CMasterNode* mn, CNode* pnode)
{
    mn->MarkValid(GetTime());
    StatusAccepted(mn);
    printf("***CMasternodeChecker::Accept Accepted masternode \n");

    if(mapTemp.count(mn->vin.prevout.ToString()))
    {
        pnode->CloseSocketDisconnect();
        mapTemp.erase(mn->vin.prevout.ToString());
        printf("CMasternodeChecker::Accept: closing connection with peer because mn verified\n");
    }
}

void CMasternodeChecker::Reject(CMasterNode* mn)
{
    mn->MarkInvalid(GetTime());
    mapRejected[mn->vin.prevout.ToString()] = *mn;

    map<string, CMasterNode>::iterator it = mapPending.find(mn->vin.prevout.ToString());
    if(it != mapPending.end())
        mapPending.erase(it);

    printf("*** CMasternodeChecker::Rejected mn at %s : Accepted=%d Pending=%d Rejected=%d\n",
           ((CAddress)mn->addr).ToString().c_str(),
           mapAccepted.size(),
           mapPending.size(),
           mapRejected.size());
}

void CMasternodeChecker::Reject(CMasterNode* mn, CNode* pnode)
{
    //disconnect from peer if we marked this as a temporary peer
    if(mapTemp.count(mn->vin.prevout.ToString()))
    {
        pnode->CloseSocketDisconnect();
        mapTemp.erase(mn->vin.prevout.ToString());
        printf("CMasternodeChecker::Reject closing connection with peer because mn failed\n");
    }

    Reject(mn);
}

void CMasternodeChecker::SendVerifyRequest(CMasterNode* mn, CNode* pnode)
{
    if(GetTime() - mn->checkTime < 30)
    {
        printf("***CMasternodeChecker::SendVerifyRequest already asked within last 30 seconds\n");
        return;
    }

    printf("***CMasternodeChecker:: Sending verify request to %s \n", pnode->addr.ToString().c_str());
    //create a hash of non deterministic random vars and ask mn to sign it
    CDataStream ss(SER_GETHASH, 0);
    ss << rand() << GetTime() << GetPendingCount();
    uint256 hash = Hash(ss.begin(), ss.end());
    printf("***Hash: %s \n", hash.ToString().c_str());

    mn->requestedHash = hash;
    mn->checkTime = GetTime();
    pnode->PushMessage("mnprove", hash);
}

void CMasternodeChecker::RequestSyncWithPeers()//accessed in net.cpp
{
    BOOST_FOREACH(CNode* pnode, vNodes)
    {
        //if(pnode->nVersion == PROTOCOL_VERSION)
       // {
            pnode->PushMessage("mncount");
            printf("CMasternodeChecker::RequestSyncWithPeers(): requesting mncount from %s\n", pnode->addr.ToString().c_str());
        //}
    }
}

void CMasternodeChecker::SendList(CNode *pnode)
{
   // ReconcileLists();

    for(map<string, CMasterNode>::iterator it = mapPending.begin(); it != mapPending.end(); it++)
    {
        CMasterNode mn = (*it).second;
        pnode->PushMessage("mnfromlist", mn.vin, mn.addr, mn.sig, mn.now, mn.pubkey, mn.pubkey2, mn.lastTimeSeen, mn.protocolVersion);
    }

    for(map<string, CMasterNode>::iterator it = mapAccepted.begin(); it != mapAccepted.end(); it++)
    {
        CMasterNode mn = (*it).second;
        pnode->PushMessage("mnfromlist", mn.vin, mn.addr, mn.sig, mn.now, mn.pubkey, mn.pubkey2, mn.lastTimeSeen, mn.protocolVersion);
    }
    printf("***CMasternodeChecker::SendList(): sending list to %s - Accepted=%d Pending=%d\n", pnode->addr.ToString().c_str(), mapAccepted.size(), mapPending.size());
}

bool CMasternodeChecker::InSync(int nCount)
{
    return GetMasternodeCount() == nCount;
}

CMasterNode* CMasternodeChecker::GetNextPending()
{
    if(mapPending.empty())
        return NULL;

    return &(*mapPending.begin()).second;
}

void CMasternodeChecker::ProcessCheckerMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv)
{
    if(strCommand == "mnprove")
    {
        printf("***CMasternodeChecker::ProcessCheckerMessage() recieved mnprove\n");
        // if we are a masternode, confirm that we are so the peer can verify the list
        if(!fMasterNode)
            return;


        //peer sends us a random hash to sign with our masternode pubkey
        uint256 hash;
        vRecv >> hash;
        printf("***CMasternodeChecker::ProcessCheckerMessage() requested hash to prove is %s \n", hash.ToString().c_str());

        CPubKey pubKeyMasternode;
        CKey keyMasternode;
        string errorMessage;
        if(!darkSendSigner.SetKey(strMasterNodePrivKey, errorMessage, keyMasternode, pubKeyMasternode))
        {
            printf("Register::ManageStatus() - Error upon calling SetKey: %s\n", errorMessage.c_str());
            return;
        }

        vector<unsigned char> vchSig;
        errorMessage = "";
        if(!darkSendSigner.SignMessage(hash.ToString(), errorMessage, vchSig, keyMasternode))
        {
            printf("***CMasternodeChecker::ProcessCheckerMessage() sign failed \n");
            return;
        }

        if(!darkSendSigner.VerifyMessage(pubKeyMasternode, vchSig, hash.ToString(), errorMessage))
            printf("CMasternodeChecker:: Verify message failed");

        printf("***CMasternodeChecker::ProcessCheckerMessage() sending proof signature\n");
        pfrom->PushMessage("mnproof", vchSig);
        return;
    }
    else if(strCommand == "mnproof")
    {
        printf("***CMasternodeChecker::ProcessCheckerMessage() recieved mnproof\n");
        vector<unsigned char> vchSig;
        vRecv >> vchSig;

        //find the masternode entry for this peer
        CMasterNode* mn = NULL;
        bool fFound = false;
        for(map<string, CMasterNode>::iterator it = mapPending.begin(); it != mapPending.end(); it++)
        {
            CMasterNode* m = &(*it).second;
            printf("***CMasternodeChecker::ProcessCheckerMessage() checking add %s vs %s \n", ((CAddress) m->addr).ToString().c_str(), pfrom->addr.ToString().c_str());
            if(((CAddress)m->addr).ToString() == pfrom->addr.ToString()) //note need to double check this logic
            {
                mn = m;
                fFound = true;
                break;
            }
        }

        if(!fFound)
        {
            printf("***CMasternodeChecker::ProcessCheckerMessage() mnprove - do not have masternode\n");
            return;
        }
        if(mn->requestedHash == uint256(0))
        {
            printf("***CMasternodeChecker::ProcessCheckerMessage() mnprove - requested hash %s\n", mn->requestedHash.ToString().c_str());
            return;
        }
        string errorMessage;
        if(!darkSendSigner.VerifyMessage(mn->pubkey2, vchSig, mn->requestedHash.ToString(), errorMessage))
        {
            //this masternode failed our verification test, this is not a valid masternode
            printf("***CMasternodeChecker::ProcessCheckerMessage() mnprove - masternode verifymessage failed mark invalid\n");
            Reject(mn, pfrom);
            return;
        }

        //this mn passed the test, mark as valid
        Accept(mn, pfrom);
        printf("***CMasternodeChecker::ProcessCheckerMessage() mnprove - masternode is valid\n");
    }
    else if(strCommand == "mncount")
    {
        printf("***CMasternodeChecker::ProcessCheckerMessage() recieved mncount, sending back count of %d\n", masternodeChecker.GetMasternodeCount());
        pfrom->PushMessage("mncounted", masternodeChecker.GetMasternodeCount());
    }
    else if(strCommand == "mncounted")
    {
        int nCount = 0;
        vRecv >> nCount;
        printf("***CMasternodeChecker::ProcessCheckerMessage() recieved mncounted of %d\n", nCount);

        //if(!InSync(nCount))
            SendList(pfrom);
    }
    else if(strCommand == "mnfromlist")
    {
        CTxIn vin;
        CService addr;
        CPubKey pubkey;
        CPubKey pubkey2;
        vector<unsigned char> vchSig;
        int64_t sigTime;
        int64_t lastUpdated;
        int protocolVersion;

        vRecv >> vin >> addr >> vchSig >> sigTime >> pubkey >> pubkey2 >> lastUpdated >> protocolVersion;
        CMasterNode mn(addr, vin, pubkey, vchSig, sigTime, pubkey2, protocolVersion);

        AddMasternode(&mn);
        printf("***CMasternodeChecker::ProcessCheckerMessage() recieved mn list from %s, size=%d\n", pfrom->addr.ToString().c_str());
    }
}
