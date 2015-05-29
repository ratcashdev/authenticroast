/**
 *    Copyright (C) 2015 Ratcash
 *
 *    This file is part of AuthenticRoast.
 *
 *    This library is free software; you can redistribute it and/or
 *    modify it under the terms of the GNU Lesser General Public
 *    License as published by the Free Software Foundation; either
 *    version 3 of the License, or (at your option) any later version.
 *
 *    This library is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *    Lesser General Public License for more details.
 *
 *    You should have received a copy of the GNU Lesser General
 *    Public License along with this library; if not, write to the
 *    Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *    Boston, MA 02110-1301 USA
 *
 *    You can reach the author and get more information about this
 *    project at: http://aikesommer.name/
 */
package name.aikesommer.authenticator;

import java.lang.annotation.Annotation;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Set;
import javax.enterprise.context.Dependent;
import javax.enterprise.context.spi.CreationalContext;
import javax.enterprise.inject.Instance;
import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.CDI;
import javax.enterprise.util.AnnotationLiteral;
import javax.naming.InitialContext;
import javax.naming.NamingException;

public class CDIHelper {

	public static <T> T getReference(Class<T> beanClass) {
		return getReference(beanClass, getBeanManager());
	}

	public static <T> T getReferenceOrNull(Class<T> beanClass,  Annotation... qualifier) {
		return getReferenceOrNull(beanClass, getBeanManager(), qualifier);
	}

	@SuppressWarnings("unchecked")
	public static <T> T getReference(Class<T> beanClass, BeanManager beanManager, Annotation... qualifier) {

		Bean<T> bean = (Bean<T>) beanManager.resolve(beanManager.getBeans(beanClass, qualifier));
		return (T) beanManager.getReference(bean, beanClass, beanManager.createCreationalContext(bean));
	}

	@SuppressWarnings("unchecked")
	public static <T> T getReferenceOrNull(Class<T> beanClass, BeanManager beanManager, Annotation... qualifier) {
		try {
			return getBeanClassInstance(beanManager, beanClass, qualifier);
//			Bean<T> bean = (Bean<T>) beanManager.resolve(beanManager.getBeans(beanClass, qualifier));
//			return (T) beanManager.getReference(bean, beanClass, beanManager.createCreationalContext(bean));
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static <T> T getInstance(final Class<T> type, final Class<? extends Annotation> scope, Annotation... qualifier) {
		return getInstance(type, scope, getBeanManager(), qualifier);
	}

	public static <T> T getInstance(final Class<T> type, final Class<? extends Annotation> scope) {
		return getInstance(type, scope, getBeanManager());
	}

	public static <T> T getInstance(final Class<T> type, final Class<? extends Annotation> scope, final BeanManager beanManager, Annotation... qualifier) {

		if(qualifier == null) {
			@SuppressWarnings("unchecked")
			Bean<T> bean = (Bean<T>) beanManager.resolve(beanManager.getBeans(type));
			return beanManager.getContext(scope).get(bean, beanManager.createCreationalContext(bean));
		} else {
			@SuppressWarnings("unchecked")
			Bean<T> bean = (Bean<T>) beanManager.resolve(beanManager.getBeans(type, qualifier));
			return beanManager.getContext(scope).get(bean, beanManager.createCreationalContext(bean));
		}
	}

	public static BeanManager tryGetBeanManager() {
		try {
			return getBeanManager();
		} catch (IllegalStateException e) {
			return null;
		}
	}

		public static BeanManager getBeanManager() {
		InitialContext context = null;
		try {
			context = new InitialContext();
			return (BeanManager) context.lookup("java:comp/BeanManager");
		} catch (NamingException e) {
			System.out.println("EE context not available. Falling back plain CDI.");
			return CDI.current().getBeanManager();
		} finally {
			closeContext(context);
		}
	}

	private static void closeContext(InitialContext context) {
		try {
			if (context != null) {
				context.close();
			}
		} catch (NamingException e) {
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * Returns a proxied bean class instance that cleans up itself
	 * @param <B>
	 * @param beanManager
	 * @param beanType
	 * @param qualifiers
	 * @return 
	 */
	public static <B> B getBeanClassInstance(BeanManager beanManager, Class<B> beanType, Annotation... qualifiers) {
		final B result;
		Set<Bean<?>> beans = beanManager.getBeans(beanType, qualifiers);
		if (beans.isEmpty()) {
			result = null;
		} else {
			final Bean<B> bean = (Bean<B>) beanManager.resolve(beans);
			if (bean == null) {
				result = null;
			} else {
				final CreationalContext<B> cc = beanManager.createCreationalContext(bean);
				final B reference = (B) beanManager.getReference(bean, beanType, cc);
				Class<? extends Annotation> scope = bean.getScope();
				if (scope.equals(Dependent.class)) {
					if (beanType.isInterface()) {
						result = (B) Proxy.newProxyInstance(bean.getBeanClass().getClassLoader(), new Class<?>[]{beanType, Finalizable.class}, new InvocationHandler() {
							@Override
							public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
								if (method.getName().equals("finalize")) {
									bean.destroy(reference, cc);
								}
								try {
									return method.invoke(reference, args);
								} catch (InvocationTargetException e) {
									throw e.getCause();
								}
							}
						});
					} else {
						throw new IllegalArgumentException("If the resolved bean is dependent scoped then the received beanType should be an interface in order to manage the destruction of the created dependent bean class instance.");
					}
				} else {
					result = reference;
				}
			}
		}
		return result;
	}


	
	public static Instance<PluggableAuthenticator> getCdiAuthenticator() {
		Instance<PluggableAuthenticator> authenticator = CDI.current().select(PluggableAuthenticator.class, 
				new AnnotationLiteral<Primary>() {});
		return authenticator;
	}
	
	interface Finalizable {

		void finalize() throws Throwable;
	}
}
