using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Microsoft.Support.Workflow.Authoring.AddIns.ErrorMessage.Config
{
    public static class UserErrorConfigConstant
    {
        public static class AttributeName
        {
            public const string ErrorCode = "errorCode";
            public const string UserMessage = "errorMessage";
        }

        public static class NodeName
        {
            public const string UserErrorMessageConfiguration = "userErrorConfiguration";
            public const string Errors = "errors";
        }
    }
}
