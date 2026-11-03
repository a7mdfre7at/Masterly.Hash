using System;
using System.Linq.Expressions;
using System.Reflection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;

namespace Masterly.Hash.EntityFrameworkCore.Internal
{
    internal static class ContextServices
    {
        private static readonly MethodInfo EfPropertyMethod = typeof(EF).GetMethod(nameof(EF.Property))!;

        /// <summary>The interceptor added by UseMasterlyHash (or AddInterceptors), or null.</summary>
        public static MasterlyHashSaveChangesInterceptor? FindInterceptor(DbContext context)
        {
            CoreOptionsExtension? core = context.GetService<IDbContextOptions>().FindExtension<CoreOptionsExtension>();
            if (core?.Interceptors == null)
                return null;
            foreach (Microsoft.EntityFrameworkCore.Diagnostics.IInterceptor interceptor in core.Interceptors)
            {
                if (interceptor is MasterlyHashSaveChangesInterceptor masterly)
                    return masterly;
            }
            return null;
        }

        public static MasterlyHashSaveChangesInterceptor RequireInterceptor(DbContext context) =>
            FindInterceptor(context) ?? throw new InvalidOperationException(
                "No MasterlyHashSaveChangesInterceptor is registered on this context. Call UseMasterlyHash when configuring it.");

        /// <summary>
        /// Name of the property selected by <c>e =&gt; e.Prop</c> or <c>e =&gt; EF.Property&lt;string&gt;(e, "Prop")</c>.
        /// </summary>
        public static string GetPropertyName(LambdaExpression selector, string paramName)
        {
            Expression body = selector.Body;
            while (body is UnaryExpression unary && (unary.NodeType == ExpressionType.Convert || unary.NodeType == ExpressionType.ConvertChecked))
                body = unary.Operand;

            ParameterExpression parameter = selector.Parameters[0];
            if (body is MemberExpression member && member.Expression == parameter && member.Member is PropertyInfo or FieldInfo)
                return member.Member.Name;

            if (body is MethodCallExpression call
                && call.Method.IsGenericMethod
                && call.Method.GetGenericMethodDefinition() == EfPropertyMethod
                && call.Arguments[0] == parameter
                && call.Arguments[1] is ConstantExpression { Value: string name })
                return name;

            throw new ArgumentException("The expression must select a property of the entity, e.g. u => u.EmailIndex.", paramName);
        }
    }
}
