#include "masternodechecker.h"
#include "masternode.h"
#include "main.h"

void CMasternodeChecker::AddMasternode(CMasterNode* mn)
{
    if(AlreadyHave(mn))
        return;

    mapPending[mn->vin] = mn;

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
    mapTemp[mn->vin] = mn;
}

void CMasternodeChecker::Reject(CMasterNode* mn)
{
    map<CTxin, CMasterNode*>::iterator it = find(mapPending.begin(), mapPending.end(), mn->vin);
    if(it != mapPending.end())
        mapPending.erase(it);

    mapRejected[mn->vin] = mn;

    //disconnect from peer if we marked this as a temporary peer
    if(mapTemp.count(mn->vin))
    {
        pnode->CloseSocketDisconnect();
        mapTemp.erase(mn->vin);
        printf("CMasternodeChecker::Reject closing connection with peer because mn failed\n");
    }
}

CMasterNode* CMasternodeChecker::GetNextPending()
{
    if(mapPending.empty())
        return NULL;

    return mapPending.front();
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

void CMasternodeChecker::Accept(CMasterNode* mn, CNode* pnode)
{
    mn->MarkValid(GetTime());
    StatusAccepted(mn);

    if(mapTemp.count(mn->vin))
    {
        pnode->CloseSocketDisconnect();
        mapTemp.erase(mn->vin);
        printf("CMasternodeChecker::Accept: closing connection with peer because mn verified\n");
    }
}
