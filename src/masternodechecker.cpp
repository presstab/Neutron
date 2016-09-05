#include "darksend.h"
#include "masternodechecker.h"
#include "masternode.h"

void CMasternodeChecker::AddMasternode(CMasterNode* mn)
{
    if(AlreadyHave(mn))
        return;

    //use a new address in memory
    CMasterNode mnNew = *mn;

    mapPending[mnNew.vin.prevout.ToString()] = &mnNew;

    BOOST_FOREACH(CNode* pnode, vNodes)
    {
        //check if we have this peer already
        if(pnode->addrLocal == mnNew.addr)
        {
            SendVerifyRequest(&mnNew, pnode);
            return;
        }
    }

    //we dont have this peer so mark as a temporary connection
    mapTemp[mnNew.vin.prevout.ToString()] = &mnNew;
}

void CMasternodeChecker::Accept(CMasterNode* mn, CNode* pnode)
{
    mn->MarkValid(GetTime());
    StatusAccepted(mn);

    if(mapTemp.count(mn->vin.prevout.ToString()))
    {
        pnode->CloseSocketDisconnect();
        mapTemp.erase(mn->vin.prevout.ToString());
        printf("CMasternodeChecker::Accept: closing connection with peer because mn verified\n");
    }
}

void CMasternodeChecker::Reject(CMasterNode* mn, CNode* pnode)
{
    map<string, CMasterNode*>::iterator it = mapPending.find(mn->vin.prevout.ToString());
    if(it != mapPending.end())
        mapPending.erase(it);

    mn->MarkInvalid(GetTime());
    mapRejected[mn->vin.prevout.ToString()] = mn;

    //disconnect from peer if we marked this as a temporary peer
    if(mapTemp.count(mn->vin.prevout.ToString()))
    {
        pnode->CloseSocketDisconnect();
        mapTemp.erase(mn->vin.prevout.ToString());
        printf("CMasternodeChecker::Reject closing connection with peer because mn failed\n");
    }
}

void CMasternodeChecker::SendVerifyRequest(CMasterNode* mn, CNode* pnode)
{
    //create a hash of non deterministic random vars and ask mn to sign it
    CDataStream ss(SER_GETHASH, 0);
    ss << rand() << GetTime() << GetPendingCount();
    uint256 hash = Hash(ss.begin(), ss.end());

    mn->requestedHash = hash;
    pnode->PushMessage("mnprove", hash);
}

void CMasternodeChecker::RequestSyncWithPeers()//put this somewhere
{
    BOOST_FOREACH(CNode* pnode, vNodes)
    {
        if(pnode->nVersion == PROTOCOL_VERSION)
        {
            pnode->PushMessage("mncount");
            printf("CMasternodeChecker::RequestSyncWithPeers(): sending mn count to %s\n", pnode->addrLocal.ToString().c_str());
        }
    }
}

void CMasternodeChecker::SendList(CNode *pnode)
{
    vector<CMasterNode> vList = GetList();
    pnode->PushMessage("mnlist", vList);
    printf("CMasternodeChecker::SendList(): sending list to %s\n", pnode->addrLocal.ToString().c_str());
}

void CMasternodeChecker::ProcessMasternodeList(vector<CMasterNode> vList)
{
    BOOST_FOREACH(CMasterNode mn, vList)
        AddMasternode(&mn);
}

bool CMasternodeChecker::InSync(int nCount)
{
    return GetMasternodeCount() == nCount;
}

CMasterNode* CMasternodeChecker::GetNextPending()
{
    if(mapPending.empty())
        return NULL;

    return (*mapPending.begin()).second;
}

void CMasternodeChecker::ProcessCheckerMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv)
{
    if(strCommand == "mnprove")
    {
        printf("CMasternodeChecker::ProcessCheckerMessage() recieved mnprove\n");
        // if we are a masternode, confirm that we are so the peer can verify the list
        if(masternodePayments.IsEnabled())
        {
            //peer sends us a random hash to sign with our masternode pubkey
            uint256 hash;
            vRecv >> hash;

            vector<unsigned char> vchSig;
            if(!masternodePayments.Sign(vchSig, hash.ToString()))
                return;

            pfrom->PushMessage("mnproof", vchSig);
        }
    }
    else if(strCommand == "mnproof")
    {
        printf("CMasternodeChecker::ProcessCheckerMessage() recieved mnproof\n");
        vector<unsigned char> vchSig;
        vRecv >> vchSig;

        //find the masternode entry for this peer
        CMasterNode* mn;
        bool fFound = false;
        BOOST_FOREACH(CMasterNode m, vecMasternodes)
        {
            if(m.addr == pfrom->addrLocal) //note need to double check this logic
            {
                mn = &m;
                fFound = true;
            }
        }

        if(!fFound || mn->requestedHash == uint256(0))
        {
            printf("CMasternodeChecker::ProcessCheckerMessage() mnprove - do not have masternode\n");
            return;
        }
        string errorMessage;
        if(!darkSendSigner.VerifyMessage(mn->pubkey2, vchSig, mn->requestedHash.ToString(), errorMessage))
        {
            //this masternode failed our verification test, this is not a valid masternode
            printf("CMasternodeChecker::ProcessCheckerMessage() mnprove - masternode verify failed mark invalid\n");
            Reject(mn, pfrom);
            return;
        }

        //this mn passed the test, mark as valid
        Accept(mn, pfrom);
        printf("CMasternodeChecker::ProcessCheckerMessage() mnprove - masternode is valid\n");
    }
    else if(strCommand == "mncount")
    {
        printf("CMasternodeChecker::ProcessCheckerMessage() recieved mncount\n");
        pfrom->PushMessage("mncounted", masternodeChecker.GetMasternodeCount());
    }
    else if(strCommand == "mncounted")
    {
        printf("CMasternodeChecker::ProcessCheckerMessage() recieved mncount of %d\n", GetMasternodeCount());
        int nCount = 0;
        vRecv >> nCount;

        //if(!InSync(nCount))
            SendList(pfrom);
    }
    else if(strCommand == "mnlist")
    {
        printf("CMasternodeChecker::ProcessCheckerMessage() recieved mn list from %s\n", pfrom->addrLocal.ToString().c_str());
        vector<CMasterNode> vList;
        vRecv >> vList;
        ProcessMasternodeList(vList);
    }




























































}
