#include "masternodechecker.h"
#include "masternode.h"

void CMasternodeChecker::AddMasternode(CMasterNode* mn)
{
    if(AlreadyHave(mn))
        return;

    mapPending[mn->vin.prevout.ToString()] = mn;

    BOOST_FOREACH(CNode* pnode, vNodes)
    {
        //check if we have this peer already
        if(pnode->addrLocal == mn->addr)
        {
            SendVerifyRequest(mn, pnode);
            return;
        }
    }

    //we dont have this peer so mark as a temporary connection
    mapTemp[mn->vin.prevout.ToString()] = mn;
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
        pnode->PushMessage("mncount");
    }
}

void CMasternodeChecker::SendList(CNode *pnode)
{
    vector<CMasterNode> vList = GetList();
    pnode->PushMessage("mnlist", vList);
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
